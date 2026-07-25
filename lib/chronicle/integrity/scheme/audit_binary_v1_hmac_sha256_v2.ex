defmodule Chronicle.Integrity.Scheme.AuditBinaryV1HMACSHA256V2 do
  @moduledoc false

  # Frozen integrity scheme. Once this identifier ships as a retained scheme,
  # changing any value or primitive below would make old evidence impossible
  # to verify. A new writer belongs in a new module and registry entry.
  @behaviour Chronicle.Integrity.Scheme

  alias Chronicle.Integrity.Entry

  @algorithm "audit-binary-v1-hmac-sha256-v2"
  @canonical Chronicle.Canonical.V1

  @impl true
  def algorithm, do: @algorithm

  @impl true
  def canonical_version, do: @canonical.version()

  @impl true
  def build(kind, record_id, payload, sequence, previous_digest, ledger, key_id, key) do
    canonical_version = canonical_version()

    # Each digest is an input to the next: content, then position, then
    # authentication. Reordering these blocks compiles to a different scheme.
    content_digest =
      {:audit_content_v2, @algorithm, canonical_version, kind, record_id,
       Chronicle.Value.canonical(payload)}
      |> canonical()
      |> sha256()

    digest =
      {:audit_chain_v2, @algorithm, canonical_version, ledger, sequence, previous_digest, kind,
       record_id, content_digest}
      |> canonical()
      |> sha256()

    signature =
      {:audit_signature_v2, @algorithm, canonical_version, ledger, sequence, digest, key_id}
      |> canonical()
      |> hmac(key)

    {:ok,
     %Entry{
       ledger: ledger,
       sequence: sequence,
       kind: kind,
       record_id: record_id,
       previous_digest: previous_digest,
       content_digest: content_digest,
       digest: digest,
       signature: signature,
       key_id: key_id,
       algorithm: @algorithm,
       canonical_version: canonical_version
     }}
  end

  @impl true
  def rebuild(%Entry{} = entry, payload, key) do
    build(
      entry.kind,
      entry.record_id,
      payload,
      entry.sequence,
      entry.previous_digest,
      entry.ledger,
      entry.key_id,
      key
    )
  end

  @impl true
  def compare(%Entry{} = stored, %Entry{} = rebuilt) do
    with :ok <-
           check(
             secure_equal?(stored.content_digest, rebuilt.content_digest),
             {:content_digest_mismatch, stored.sequence}
           ),
         :ok <-
           check(
             secure_equal?(stored.digest, rebuilt.digest),
             {:chain_digest_mismatch, stored.sequence}
           ),
         :ok <-
           check(
             secure_equal?(stored.signature, rebuilt.signature),
             {:signature_mismatch, stored.sequence}
           ) do
      :ok
    end
  end

  defp canonical(term), do: @canonical.encode(term)

  defp sha256(value) do
    :crypto.hash(:sha256, value)
    |> Base.encode16(case: :lower)
  end

  defp hmac(value, key) do
    :crypto.mac(:hmac, :sha256, key, value)
    |> Base.encode16(case: :lower)
  end

  defp secure_equal?(left, right) when is_binary(left) and is_binary(right) do
    byte_size(left) == byte_size(right) and :crypto.hash_equals(left, right)
  end

  defp secure_equal?(_left, _right), do: false

  defp check(true, _error), do: :ok
  defp check(false, error), do: {:error, error}
end
