defmodule Chronicle.Digest do
  @moduledoc false

  # Every hash in the library passes through this module, which is the whole
  # reason it exists: the algorithm and the output encoding are chosen once,
  # here, instead of at each call site that happens to need a digest.
  #
  # The two functions are deliberately ignorant. They hash the bytes they are
  # handed and know nothing about what those bytes mean. Domain separation --
  # the tagged tuples that stop a content digest from ever being mistaken for
  # a chain digest or a signature -- belongs to `Chronicle.Integrity` and is
  # applied before the bytes arrive here. Hashing a raw value through this
  # module, outside one of those tuples, is a bug at the call site rather
  # than a bug in this file.
  #
  # Output is lowercase hex rather than the raw bytes `:crypto` returns. Hex
  # costs twice the storage and buys three things: the digests sit in text
  # columns that PostgreSQL and SQLite treat identically, they survive the
  # trip through a JSON payload unharmed, and an operator reading the table
  # in psql can compare two rows by eye.
  #
  # The lowercase part looks cosmetic and is not. A digest produced here is
  # itself hashed into the next link of the chain, so the case of every
  # character is signed content. Switching to `:upper` would not be a
  # formatting change, it would invalidate every chain ever written.
  #
  # Nothing here compares digests. When a value from this module stands in
  # for a signature, comparing it with `==` leaks how many leading bytes a
  # forgery got right; `Chronicle.Integrity` does that comparison in constant
  # time, next to the code that knows a signature is what it is holding.

  @doc """
  Hashes already-encoded bytes, returning lowercase hex.

  Anyone holding the content can recompute this, which is what makes it a
  fingerprint rather than a signature. It proves that content has not changed,
  not that it was written by someone entitled to write it.

  What goes in is the caller's problem. This digests exactly the bytes it is
  given, so two values that ought to hash differently must already differ by
  the time they arrive -- through canonical encoding, and through the domain
  tag naming which kind of digest is being taken.
  """
  @spec sha256(binary()) :: String.t()
  def sha256(value) when is_binary(value) do
    :crypto.hash(:sha256, value)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Authenticates bytes with a secret key, returning lowercase hex.

  Unlike `sha256/1`, this cannot be produced without the key. An attacker who
  rewrites a row can recompute its content digest freely; they cannot forge
  this. It is the step that turns "the chain is internally consistent" into
  "the chain was written by this application".

  Mind the argument order: the key comes first, then the value being signed.
  Reversing them yields a digest that is well-formed, stable, and authenticates
  nothing at all, and no verification downstream will notice. Callers that
  pipe the subject deliberately flip the order in a local helper -- see
  `Chronicle.Integrity` -- which is the safer place for that inversion to live
  precisely because it is written once.
  """
  @spec hmac_sha256(binary(), binary()) :: String.t()
  def hmac_sha256(key, value) when is_binary(key) and is_binary(value) do
    :crypto.mac(:hmac, :sha256, key, value)
    |> Base.encode16(case: :lower)
  end
end
