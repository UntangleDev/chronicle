defmodule Chronicle.Canonical do
  @moduledoc """
  Versioned, deterministic encoding for integrity-protected audit data.

  The encoding is deliberately independent of Erlang's External Term Format.
  `:erlang.term_to_binary/2` does not guarantee identical output across major
  OTP releases, which makes it unsuitable as the permanent input to an audit
  signature.

  Version 1 is a small, self-delimiting binary format. Every value begins with
  a one-byte type tag. Variable-width values carry unsigned 32-bit big-endian
  lengths, maps are sorted by the complete encoded key bytes, integers use a
  sign byte plus an unsigned magnitude, and floats use their IEEE-754 binary64
  representation. Runtime-bearing terms are rejected.

  The leading byte returned by `encode/1` is the format version. Nested values
  do not repeat it. Version 1 fixes the following resource limits as part of
  the format contract: nesting depth 64, collection length 100,000, individual
  binary length 16 MiB, integer-magnitude length 4 KiB, and encoded term
  length 32 MiB. Changing those limits requires a new canonical version.

  ## Determinism is the entire requirement

  Two terms a caller would consider equal must produce identical bytes, on
  every machine and every OTP release, indefinitely. A digest is evidence only
  if the thing it commits to can be reproduced exactly at verification time,
  which may be years later on hardware that does not exist yet.

  Three decisions follow from that, and each is easy to undo by accident:

    * **Maps are sorted by their fully encoded key bytes**, not left in
      iteration order. Iteration order on the BEAM is an implementation
      detail: it depends on a map's internal representation, which changes as
      the map grows, and it carries no cross-release guarantee. Sorting on the
      encoded bytes removes the dependency rather than betting an archive on
      it holding.
    * **Every value carries a type tag**, so a binary can never be read as an
      integer that happens to share its bytes.
    * **Collections carry an element count and a byte length.** The redundancy
      is deliberate. It makes the framing unambiguous, so no two distinct
      terms can be encoded into the same bytes — which is the property the
      digest above it depends on.

  ## Why unsupported terms are refused rather than coerced

  Structs are rejected even though `%Foo{}` is a map and would otherwise
  encode happily. A struct's shape is code, and code changes independently of
  data signed under it, so normalization belongs to a layer that knows what
  the struct means. Pids, ports, references and functions are rejected because
  they do not survive a restart: a digest over a pid commits to something that
  can never be reproduced, so it would verify once and fail forever after.

  ## The limits are a defence, not tuning

  Encoding runs inside the caller's transaction, while the ledger lock is
  held. An unbounded term therefore becomes unbounded time holding a lock that
  serialises every other audited write. The ceilings bound that work, which is
  also why `bounded_list_length!/1` walks a list against the limit instead of
  calling `length/1` — a hostile ten-million-element list is refused after a
  hundred thousand steps rather than counted in full first.
  """

  # Normative: these are the format contract quoted in the moduledoc above,
  # not tuning knobs. Changing any of them changes which terms encode at all,
  # so it requires a new @version, and the documentation moves with it.
  @version 1
  @max_depth 64
  @max_collection_length 100_000
  @max_binary_bytes 16 * 1_024 * 1_024
  @max_integer_bytes 4 * 1_024
  @max_encoded_bytes 32 * 1_024 * 1_024

  @type version :: pos_integer()

  @doc """
  The canonical version this build writes.

  Stored on every entry and hashed into every digest, so an entry written
  under an older version is refused at verification rather than checked under
  rules it was never written for.
  """
  @spec version() :: version()
  def version, do: @version

  @doc """
  Encodes a term to its canonical bytes, raising on anything unrepresentable.

  This raises rather than returning an error tuple because reaching it with an
  unsupported term is a programmer error: callers normalize through
  `Chronicle.Value` first, and everything that survives normalization is
  encodable by construction. A raise here means that contract was skipped.
  """
  @spec encode(term()) :: binary()
  def encode(term) do
    encoded = encode_value(term, 0)
    ensure_size!(byte_size(encoded) + 1, @max_encoded_bytes, "encoded term")
    <<@version, encoded::binary>>
  end

  defp encode_value(value, depth) do
    ensure_depth!(depth)
    encode_typed(value, depth)
  end

  defp encode_typed(nil, _depth), do: <<0x00>>
  defp encode_typed(false, _depth), do: <<0x01>>
  defp encode_typed(true, _depth), do: <<0x02>>

  defp encode_typed(value, _depth) when is_integer(value) do
    sign = if value < 0, do: 1, else: 0
    absolute = abs(value)
    maximum = Bitwise.bsl(1, @max_integer_bytes * 8)

    if absolute >= maximum do
      raise ArgumentError,
            "Chronicle canonical integer magnitude exceeds #{@max_integer_bytes} bytes"
    end

    magnitude = :binary.encode_unsigned(absolute, :big)
    ensure_size!(byte_size(magnitude), @max_integer_bytes, "integer magnitude")
    <<0x03, sign, byte_size(magnitude)::32-big, magnitude::binary>>
  end

  defp encode_typed(value, _depth) when is_binary(value) do
    ensure_size!(byte_size(value), @max_binary_bytes, "binary")
    <<0x04, byte_size(value)::32-big, value::binary>>
  end

  # The BEAM has no non-finite floats: overflowing arithmetic raises, and
  # neither binary matching nor term decoding will construct one. There is
  # nothing to guard against here.
  defp encode_typed(value, _depth) when is_float(value), do: <<0x05, value::float-64>>

  defp encode_typed(value, _depth) when is_atom(value) do
    bytes = Atom.to_string(value)
    <<0x06, byte_size(bytes)::32-big, bytes::binary>>
  end

  defp encode_typed(value, depth) when is_list(value) do
    length = bounded_list_length!(value)
    encoded = value |> Enum.map(&encode_value(&1, depth + 1)) |> IO.iodata_to_binary()
    ensure_size!(byte_size(encoded), @max_encoded_bytes, "encoded list")
    <<0x07, length::32-big, byte_size(encoded)::32-big, encoded::binary>>
  end

  defp encode_typed(value, depth) when is_tuple(value) do
    ensure_collection_length!(tuple_size(value), "tuple")
    values = Tuple.to_list(value)
    encoded = values |> Enum.map(&encode_value(&1, depth + 1)) |> IO.iodata_to_binary()
    ensure_size!(byte_size(encoded), @max_encoded_bytes, "encoded tuple")
    <<0x08, tuple_size(value)::32-big, byte_size(encoded)::32-big, encoded::binary>>
  end

  defp encode_typed(%_{} = value, _depth) do
    raise ArgumentError,
          "Chronicle canonical encoding does not support structs; " <>
            "normalize #{inspect(value.__struct__)} first"
  end

  defp encode_typed(value, depth) when is_map(value) do
    ensure_collection_length!(map_size(value), "map")

    entries =
      value
      |> Enum.map(fn {key, item} ->
        {encode_value(key, depth + 1), encode_value(item, depth + 1)}
      end)
      # Sorting on the encoded key, not the original term. Term order and
      # byte order disagree — `:b` sorts before `"a"` as terms — and it is the
      # bytes a verifier reproduces, so the bytes are what must be ordered.
      |> Enum.sort_by(fn {key, _item} -> key end)

    encoded =
      entries
      |> Enum.map(fn {key, item} -> [key, item] end)
      |> IO.iodata_to_binary()

    ensure_size!(byte_size(encoded), @max_encoded_bytes, "encoded map")
    <<0x09, map_size(value)::32-big, byte_size(encoded)::32-big, encoded::binary>>
  end

  defp encode_typed(value, _depth) do
    raise ArgumentError,
          "Chronicle canonical encoding does not support #{term_type(value)}; " <>
            "normalize it to nil, a boolean, number, binary, atom, list, tuple, or map"
  end

  # Not `length/1`. This counts against the ceiling as it walks, so a hostile
  # list costs the limit rather than its own length, and an improper tail is
  # caught by the same pass instead of raising from inside a BIF.
  defp bounded_list_length!(list), do: bounded_list_length!(list, 0)

  defp bounded_list_length!([], length), do: length

  defp bounded_list_length!([_head | tail], length)
       when length < @max_collection_length,
       do: bounded_list_length!(tail, length + 1)

  defp bounded_list_length!([_head | _tail], _length) do
    raise ArgumentError,
          "Chronicle canonical list exceeds maximum length #{@max_collection_length}"
  end

  defp bounded_list_length!(_improper, _length) do
    raise ArgumentError, "Chronicle canonical encoding requires proper lists"
  end

  defp ensure_collection_length!(length, _kind) when length <= @max_collection_length, do: :ok

  defp ensure_collection_length!(length, kind) do
    raise ArgumentError,
          "Chronicle canonical #{kind} length #{length} exceeds #{@max_collection_length}"
  end

  defp ensure_depth!(depth) when depth <= @max_depth, do: :ok

  defp ensure_depth!(depth) do
    raise ArgumentError,
          "Chronicle canonical nesting depth #{depth} exceeds #{@max_depth}"
  end

  defp ensure_size!(size, maximum, _kind) when size <= maximum, do: :ok

  defp ensure_size!(size, maximum, kind) do
    raise ArgumentError,
          "Chronicle canonical #{kind} size #{size} exceeds #{maximum} bytes"
  end

  defp term_type(value) when is_bitstring(value), do: "a non-binary bitstring"
  defp term_type(value) when is_function(value), do: "a function"
  defp term_type(value) when is_pid(value), do: "a pid"
  defp term_type(value) when is_port(value), do: "a port"
  defp term_type(value) when is_reference(value), do: "a reference"
  defp term_type(_value), do: "this term"
end
