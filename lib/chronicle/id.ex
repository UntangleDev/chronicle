defmodule Chronicle.ID do
  @moduledoc false

  # UUID v4, generated here rather than pulled in as a dependency for one
  # function. The rewritten nibbles are the RFC 4122 version and variant
  # markers, which is why the random bytes are taken apart and reassembled
  # instead of being hex-encoded directly.
  #
  # `:crypto.strong_rand_bytes/1` rather than `:rand`: these ids end up as
  # primary keys in an append-only ledger, and a predictable id is one an
  # attacker can reference, collide with, or check for the existence of.

  @spec generate() :: String.t()
  def generate do
    <<a::48, _version::4, b::12, _variant::2, c::62>> = :crypto.strong_rand_bytes(16)

    raw = <<a::48, 4::4, b::12, 2::2, c::62>>
    hex = Base.encode16(raw, case: :lower)

    Enum.join(
      [
        binary_part(hex, 0, 8),
        binary_part(hex, 8, 4),
        binary_part(hex, 12, 4),
        binary_part(hex, 16, 4),
        binary_part(hex, 20, 12)
      ],
      "-"
    )
  end
end
