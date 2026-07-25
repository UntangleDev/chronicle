defmodule Chronicle.Store do
  @moduledoc """
  Resolved configuration for a named audit destination.
  """

  @enforce_keys [:name, :provider]
  defstruct [:name, :provider, options: []]

  @type t :: %__MODULE__{
          name: atom(),
          provider: module(),
          options: keyword()
        }
end
