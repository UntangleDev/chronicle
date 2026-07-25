defmodule Chronicle.Integrity.Scheme do
  @moduledoc false

  # A retained scheme is the complete recipe needed to reproduce an entry:
  # tuple shapes and tags, canonical version, hash and MAC primitives, output
  # encoding, and comparison rules. The registry is deliberately closed;
  # application configuration cannot nominate executable verifier code.

  alias Chronicle.Integrity.Entry

  @callback algorithm() :: String.t()
  @callback canonical_version() :: pos_integer()

  @callback build(
              :event | :group,
              String.t(),
              term(),
              pos_integer(),
              String.t() | nil,
              String.t(),
              String.t(),
              binary()
            ) :: {:ok, Entry.t()}

  @callback rebuild(Entry.t(), term(), binary()) :: {:ok, Entry.t()}
  @callback compare(Entry.t(), Entry.t()) :: :ok | {:error, term()}
end
