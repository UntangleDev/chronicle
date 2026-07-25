defmodule Chronicle.Canonical.V1 do
  @moduledoc false

  # Frozen canonical version 1. Once a released integrity scheme names this
  # module, changing a tag, limit, framing rule, sort rule, or accepted value
  # would destroy the ability to reproduce historical signatures. A future
  # format belongs in another module and in Chronicle.Canonical's registry.
  @version 1
  @max_depth 64
  @max_collection_length 100_000
  @max_binary_bytes 16 * 1_024 * 1_024
  @max_integer_bytes 4 * 1_024
  @max_encoded_bytes 32 * 1_024 * 1_024
  @collection_header_bytes 9

  @spec version() :: 1
  def version, do: @version

  @spec encode(term()) :: binary()
  def encode(term) do
    {encoded, _size} = encode_value(term, 0, @max_encoded_bytes - 1)
    IO.iodata_to_binary([<<@version>>, encoded])
  end

  @spec decode(binary()) :: {:ok, term()} | {:error, term()}
  def decode(<<@version, encoded::binary>>) when byte_size(encoded) < @max_encoded_bytes do
    with {:ok, value, <<>>} <- decode_value(encoded, 0) do
      {:ok, value}
    else
      {:ok, _value, _trailing} -> {:error, :trailing_canonical_bytes}
      {:error, _reason} = error -> error
    end
  end

  def decode(_encoded), do: {:error, :invalid_canonical_encoding}

  defp encode_value(value, depth, budget) do
    ensure_depth!(depth)
    encode_typed(value, depth, budget)
  end

  defp encode_typed(nil, _depth, budget), do: fixed(<<0x00>>, budget)
  defp encode_typed(false, _depth, budget), do: fixed(<<0x01>>, budget)
  defp encode_typed(true, _depth, budget), do: fixed(<<0x02>>, budget)

  defp encode_typed(value, _depth, budget) when is_integer(value) do
    sign = if value < 0, do: 1, else: 0
    absolute = abs(value)
    maximum = Bitwise.bsl(1, @max_integer_bytes * 8)

    if absolute >= maximum do
      raise ArgumentError,
            "Chronicle canonical integer magnitude exceeds #{@max_integer_bytes} bytes"
    end

    magnitude = :binary.encode_unsigned(absolute, :big)
    ensure_size!(byte_size(magnitude), @max_integer_bytes, "integer magnitude")
    encoded = <<0x03, sign, byte_size(magnitude)::32-big, magnitude::binary>>
    fixed(encoded, budget)
  end

  defp encode_typed(value, _depth, budget) when is_binary(value) do
    length = byte_size(value)
    ensure_size!(length, @max_binary_bytes, "binary")
    size = length + 5
    ensure_budget!(size, budget)
    {[<<0x04, length::32-big>>, value], size}
  end

  # The BEAM has no non-finite floats: overflowing arithmetic raises, and
  # neither binary matching nor term decoding will construct one. There is
  # nothing to guard against here.
  defp encode_typed(value, _depth, budget) when is_float(value),
    do: fixed(<<0x05, value::float-64>>, budget)

  defp encode_typed(value, _depth, budget) when is_atom(value) do
    bytes = Atom.to_string(value)
    fixed(<<0x06, byte_size(bytes)::32-big, bytes::binary>>, budget)
  end

  defp encode_typed(value, depth, budget) when is_list(value) do
    length = bounded_list_length!(value)
    encode_collection(0x07, length, value, depth, budget, "list")
  end

  defp encode_typed(value, depth, budget) when is_tuple(value) do
    length = tuple_size(value)
    ensure_collection_length!(length, "tuple")
    encode_collection(0x08, length, Tuple.to_list(value), depth, budget, "tuple")
  end

  defp encode_typed(%_{} = value, _depth, _budget) do
    raise ArgumentError,
          "Chronicle canonical encoding does not support structs; " <>
            "normalize #{inspect(value.__struct__)} first"
  end

  defp encode_typed(value, depth, budget) when is_map(value) do
    length = map_size(value)
    ensure_collection_length!(length, "map")
    body_budget = collection_body_budget!(budget)

    # Keys must be materialised for deterministic byte sorting. Values are not
    # touched until all keys have been proven to fit, then are encoded in that
    # stable order so an over-budget prefix stops before later values.
    {keys, key_bytes} =
      Enum.reduce(value, {[], 0}, fn {key, item}, {keys, used} ->
        {encoded_key, size} = encode_value(key, depth + 1, body_budget - used)
        key = IO.iodata_to_binary(encoded_key)
        {[{key, item} | keys], used + size}
      end)

    {entries, body_size} =
      keys
      |> Enum.sort_by(fn {key, _item} -> key end)
      |> Enum.reduce({[], key_bytes}, fn {key, item}, {entries, used} ->
        {encoded_item, size} = encode_value(item, depth + 1, body_budget - used)
        {[[key, encoded_item] | entries], used + size}
      end)

    header = <<0x09, length::32-big, body_size::32-big>>
    {[header, Enum.reverse(entries)], @collection_header_bytes + body_size}
  end

  defp encode_typed(value, _depth, _budget) do
    raise ArgumentError,
          "Chronicle canonical encoding does not support #{term_type(value)}; " <>
            "normalize it to nil, a boolean, number, binary, atom, list, tuple, or map"
  end

  defp encode_collection(tag, length, values, depth, budget, kind) do
    body_budget = collection_body_budget!(budget)

    {encoded, body_size} =
      Enum.reduce(values, {[], 0}, fn item, {items, used} ->
        {encoded_item, size} = encode_value(item, depth + 1, body_budget - used)
        {[encoded_item | items], used + size}
      end)

    ensure_size!(body_size, @max_encoded_bytes, "encoded #{kind}")
    header = <<tag, length::32-big, body_size::32-big>>
    {[header, Enum.reverse(encoded)], @collection_header_bytes + body_size}
  end

  defp collection_body_budget!(budget) do
    ensure_budget!(@collection_header_bytes, budget)
    min(@max_encoded_bytes, budget - @collection_header_bytes)
  end

  defp fixed(encoded, budget) do
    size = byte_size(encoded)
    ensure_budget!(size, budget)
    {encoded, size}
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

  defp ensure_budget!(size, budget) when size <= budget, do: :ok

  defp ensure_budget!(size, budget) do
    used = @max_encoded_bytes - max(budget, 0) + size

    raise ArgumentError,
          "Chronicle canonical encoded term size #{used} exceeds #{@max_encoded_bytes} bytes"
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

  defp decode_value(_encoded, depth) when depth > @max_depth,
    do: {:error, {:canonical_depth_exceeded, depth}}

  defp decode_value(<<0x00, rest::binary>>, _depth), do: {:ok, nil, rest}
  defp decode_value(<<0x01, rest::binary>>, _depth), do: {:ok, false, rest}
  defp decode_value(<<0x02, rest::binary>>, _depth), do: {:ok, true, rest}

  defp decode_value(<<0x03, sign, length::32-big, rest::binary>>, _depth)
       when sign in [0, 1] and length > 0 and length <= @max_integer_bytes do
    with {:ok, magnitude, trailing} <- take(rest, length) do
      integer = :binary.decode_unsigned(magnitude, :big)
      {:ok, if(sign == 1, do: -integer, else: integer), trailing}
    end
  end

  defp decode_value(<<0x04, length::32-big, rest::binary>>, _depth)
       when length <= @max_binary_bytes do
    with {:ok, value, trailing} <- take(rest, length), do: {:ok, value, trailing}
  end

  defp decode_value(<<0x05, value::float-64, rest::binary>>, _depth),
    do: {:ok, value, rest}

  defp decode_value(<<0x06, length::32-big, rest::binary>>, _depth)
       when length <= @max_binary_bytes do
    with {:ok, name, trailing} <- take(rest, length),
         {:ok, atom} <- existing_atom(name) do
      {:ok, atom, trailing}
    end
  end

  defp decode_value(<<0x07, count::32-big, length::32-big, rest::binary>>, depth)
       when count <= @max_collection_length and length <= @max_encoded_bytes do
    decode_collection(:list, count, length, rest, depth)
  end

  defp decode_value(<<0x08, count::32-big, length::32-big, rest::binary>>, depth)
       when count <= @max_collection_length and length <= @max_encoded_bytes do
    decode_collection(:tuple, count, length, rest, depth)
  end

  defp decode_value(<<0x09, count::32-big, length::32-big, rest::binary>>, depth)
       when count <= @max_collection_length and length <= @max_encoded_bytes do
    with {:ok, body, trailing} <- take(rest, length),
         {:ok, pairs, <<>>} <- decode_pairs(body, count, depth + 1, []),
         map <- Map.new(pairs),
         true <- map_size(map) == count do
      {:ok, map, trailing}
    else
      false -> {:error, :duplicate_canonical_map_key}
      {:ok, _pairs, _body_trailing} -> {:error, :invalid_canonical_map_length}
      {:error, _reason} = error -> error
    end
  end

  defp decode_value(_encoded, _depth), do: {:error, :invalid_canonical_encoding}

  defp decode_collection(kind, count, length, rest, depth) do
    with {:ok, body, trailing} <- take(rest, length),
         {:ok, values, <<>>} <- decode_values(body, count, depth + 1, []) do
      value = if kind == :tuple, do: List.to_tuple(values), else: values
      {:ok, value, trailing}
    else
      {:ok, _values, _body_trailing} -> {:error, :invalid_canonical_collection_length}
      {:error, _reason} = error -> error
    end
  end

  defp decode_values(rest, 0, _depth, values), do: {:ok, Enum.reverse(values), rest}

  defp decode_values(encoded, count, depth, values) do
    with {:ok, value, rest} <- decode_value(encoded, depth) do
      decode_values(rest, count - 1, depth, [value | values])
    end
  end

  defp decode_pairs(rest, 0, _depth, pairs), do: {:ok, Enum.reverse(pairs), rest}

  defp decode_pairs(encoded, count, depth, pairs) do
    with {:ok, key, rest} <- decode_value(encoded, depth),
         {:ok, value, trailing} <- decode_value(rest, depth) do
      decode_pairs(trailing, count - 1, depth, [{key, value} | pairs])
    end
  end

  defp take(binary, length) when byte_size(binary) >= length do
    <<value::binary-size(^length), rest::binary>> = binary
    {:ok, value, rest}
  end

  defp take(_binary, _length), do: {:error, :truncated_canonical_encoding}

  defp existing_atom(name) do
    {:ok, String.to_existing_atom(name)}
  rescue
    ArgumentError -> {:error, :unknown_canonical_atom}
  end
end
