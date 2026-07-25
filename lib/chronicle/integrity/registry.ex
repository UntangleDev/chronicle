defmodule Chronicle.Integrity.Registry do
  @moduledoc false

  # Closed allowlist: stored rows select data, never executable modules. Add a
  # module here when the writer changes and retain every released predecessor
  # for the full evidence-retention horizon.
  alias Chronicle.Integrity.Scheme.AuditBinaryV1HMACSHA256V2

  @current AuditBinaryV1HMACSHA256V2
  @schemes [AuditBinaryV1HMACSHA256V2]

  @spec current() :: module()
  def current, do: @current

  @spec fetch(String.t(), non_neg_integer()) :: {:ok, module()} | {:error, term()}
  def fetch(algorithm, canonical_version) do
    case Enum.find(@schemes, fn scheme ->
           scheme.algorithm() == algorithm and scheme.canonical_version() == canonical_version
         end) do
      nil ->
        if Enum.any?(@schemes, &(&1.algorithm() == algorithm)) do
          {:error, {:unsupported_canonical_version, canonical_version}}
        else
          {:error, {:unsupported_algorithm, algorithm}}
        end

      scheme ->
        {:ok, scheme}
    end
  end
end
