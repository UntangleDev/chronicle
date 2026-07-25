defmodule Chronicle.Key do
  @moduledoc """
  A signing key descriptor with an explicit ledger sequence epoch.

  `source` is resolved lazily by `Chronicle.Integrity`; it may be raw key material,
  an environment reference, or a zero-arity function. Keeping the epoch beside
  the key prevents a retained historical key from authenticating new entries.

  ## Epochs are measured in ledger sequence, not in time

  This is the decision the rest of key handling rests on, and it is worth
  understanding before adding a `:from` that looks like a date.

  A rotation expressed in wall-clock terms — "this key was retired at
  midnight" — cannot be checked. Timestamps are not signed, clocks are not
  trustworthy, and the party you are defending against is frequently the one
  who can set them. A rotation expressed as a sequence boundary is checkable
  against data that is signed: sequence numbers are covered by the chain
  digest, they increase under a lock, and an entry cannot claim a position it
  does not hold.

  So `from` and `through` are ledger positions. "Key 1 is valid through
  sequence 10,000" is a statement a verifier can enforce years later with
  nothing but the ledger in front of it, which is the only kind of statement
  worth making here.

  `through: nil` means the key is still current and has no upper bound yet.
  """

  @enforce_keys [:id, :source]
  defstruct [:id, :source, from: 1, through: nil, metadata: %{}]

  @type source ::
          binary()
          | {:base64, binary()}
          | {:system, binary()}
          | {:system, binary(), :base64}
          | (-> term())

  @type t :: %__MODULE__{
          id: String.t(),
          source: source(),
          from: pos_integer(),
          through: pos_integer() | nil,
          metadata: map()
        }

  @spec valid_at?(t(), pos_integer()) :: boolean()
  def valid_at?(%__MODULE__{from: first, through: last}, sequence)
      when is_integer(sequence) and sequence > 0 do
    sequence >= first and (is_nil(last) or sequence <= last)
  end
end
