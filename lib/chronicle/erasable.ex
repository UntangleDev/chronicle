defmodule Chronicle.Erasable do
  @moduledoc """
  Write-time marker for a value protected by a destroyable data-encryption key.

  Applications normally build this through `Chronicle.erasable/2`. The marker
  itself is never stored: normalization replaces it with an authenticated
  ciphertext envelope that contains only an opaque key identifier.
  """

  @enforce_keys [:value, :key_id]
  defstruct [:value, :key_id]

  @type t :: %__MODULE__{value: term(), key_id: String.t()}
end
