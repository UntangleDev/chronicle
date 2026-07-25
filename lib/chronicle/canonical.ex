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

  Two terms that are exactly equal after `Chronicle.Value` normalization must
  produce identical bytes, on every machine and every OTP release,
  indefinitely. A digest is evidence only if the thing it commits to can be
  reproduced exactly at verification time, which may be years later on
  hardware that does not exist yet.

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

  ## Historical versions are retained

  `encode/1` uses the current writer. Integrity verification dispatches the
  version stored on each entry through a fixed registry, so adding a new writer
  does not remove the implementation needed to reproduce older evidence.
  Existing version modules are immutable format contracts: change by adding a
  version, never by editing a retained one.

  ## Why unsupported terms are refused rather than coerced

  Structs are rejected even though `%Foo{}` is a map and would otherwise
  encode happily. A struct's shape is code, and code changes independently of
  data signed under it, so normalization belongs to a layer that knows what
  the struct means. Pids, ports, references and functions are rejected because
  they do not survive a restart: a digest over a pid commits to something that
  can never be reproduced, so it would verify once and fail forever after.

  ## The limits are a defence, not tuning

  Encoding runs inside the caller's transaction, while the ledger lock is
  held. Every encoder carries the remaining byte budget into the next child
  and stops before crossing it. Large binaries remain referenced as iodata
  until the accepted term is flattened once. The ceilings therefore bound both
  the accepted output and the work performed before rejection.
  """

  @current Chronicle.Canonical.V1
  @encoders [Chronicle.Canonical.V1]

  @type version :: pos_integer()

  @doc """
  The canonical version this build writes.

  Stored on every entry and hashed into every digest. Historical verification
  selects the frozen encoder named by the stored version rather than assuming
  this current value.
  """
  @spec version() :: version()
  def version, do: @current.version()

  @doc """
  Encodes a term with the current canonical writer.

  This raises rather than returning an error tuple because reaching it with an
  unsupported term is a programmer error: callers normalize through
  `Chronicle.Value` first, and everything that survives normalization is
  encodable by construction. A raise here means that contract was skipped.
  """
  @spec encode(term()) :: binary()
  def encode(term), do: @current.encode(term)

  @doc false
  @spec encode(term(), version()) :: binary()
  def encode(term, version) do
    case encoder(version) do
      nil -> raise ArgumentError, "unsupported Chronicle canonical version: #{inspect(version)}"
      encoder -> encoder.encode(term)
    end
  end

  @doc false
  @spec decode(binary()) :: {:ok, term()} | {:error, term()}
  def decode(<<version, _rest::binary>> = encoded) do
    case encoder(version) do
      nil -> {:error, {:unsupported_canonical_version, version}}
      encoder -> encoder.decode(encoded)
    end
  end

  def decode(_encoded), do: {:error, :invalid_canonical_encoding}

  defp encoder(version), do: Enum.find(@encoders, &(&1.version() == version))
end
