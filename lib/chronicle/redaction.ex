defmodule Chronicle.Sensitive do
  @moduledoc """
  Explicit marker returned by `Chronicle.secret/1`, `Chronicle.hash/1`, and
  `Chronicle.omit/0`.

  Applications normally use those constructors rather than building this
  struct directly.
  """
  @enforce_keys [:strategy]
  defstruct [:strategy, :value]

  @type t :: %__MODULE__{strategy: :redact | :hash | :omit, value: term()}
end

defmodule Chronicle.Redaction.Policy do
  @moduledoc """
  A resolved protection policy.

  Built once per event by `Chronicle.Redaction.compile/1` so field lookups do
  not re-read application configuration for every key in a payload.
  """

  @enforce_keys [:redact, :hash, :omit, :builtin?]
  defstruct [:redact, :hash, :omit, :builtin?]

  @type t :: %__MODULE__{
          redact: MapSet.t(String.t()),
          hash: MapSet.t(String.t()),
          omit: MapSet.t(String.t()),
          builtin?: boolean()
        }
end

defmodule Chronicle.Redaction do
  @moduledoc """
  Central protection policy for event data and Ecto record snapshots.

  Protection is applied by field name, recursively, at every nesting depth.
  A protected field is never written to the ledger in clear text.

  ## Built-in protection

  Chronicle protects credential-shaped field names by default. Detection is
  deliberately generous because an audit ledger is append-only: a value written
  in clear text cannot be removed later without breaking the hash chain.

  A field is protected when its name

    * contains `password`, `passwd`, `secret`, `token`, `credential`,
      `apikey`, `privkey`, or `passphrase`; or
    * has an underscore-separated segment equal to `pwd`, `ssn`, `cvv`, `cvc`,
      `iban`, `pin`, `salt`, or `jwt`; or
    * exactly matches a known credential or financial identifier such as
      `api_key`, `card_number`, or `routing_number`.

  Built-in protection covers credentials, not general personal data. Classify
  application-specific personal data explicitly.

  ## Configuration

  Configured fields **extend** the built-in list:

      config :chronicle,
        redaction: [
          fields: [:internal_note],
          hash_fields: [:email],
          omit_fields: [:raw_response]
        ]

  Adding one field never silently disables built-in protection. To take
  complete ownership of the policy, opt out explicitly:

      config :chronicle,
        redaction: [builtin: false, fields: [:password, :token]]

  ## Effect on Ecto record versions

  A withheld field cannot be reconstructed, so a snapshot containing one is
  reported as incomplete and `Chronicle.at/2` and `Chronicle.revert/2` fail
  closed rather than inventing a value. `mix chronicle.doctor` lists the
  withheld fields of every audited schema so this is a visible decision.

  Ecto schemas may instead declare `erasable: [field: :privacy_key_id]`.
  Chronicle stores authenticated ciphertext and reconstructs it while the
  named external key exists. Destroying that key makes later reconstruction
  fail without invalidating the signed chain.

  ## What name matching structurally cannot see

  Every rule here matches on a field *name*, which means a sensitive value that
  never sits under a name is invisible to all of them. A secret embedded in a
  free-text `description`, a token inside an error message being logged as
  context, an element of a list whose own key did not match — none of these are
  protected, and no amount of extending the name lists will reach them.

  This is not a gap to be closed later; it is the boundary of what the approach
  can do. Values that carry their sensitivity in content rather than in naming
  have to be marked at the point they enter, with `Chronicle.secret/1`,
  `Chronicle.hash/1`, or `Chronicle.omit/0`. Those markers are the escape hatch
  precisely because the policy cannot infer what it cannot name.
  """

  alias Chronicle.{Erasable, Sensitive}
  alias Chronicle.Redaction.Policy

  @substrings ~w(password passwd secret token credential apikey privkey passphrase)
  @segments ~w(pwd ssn cvv cvc iban pin salt jwt)
  @names ~w(
    api_key access_key encryption_key signing_key master_key license_key
    session_key recovery_codes backup_codes card_number credit_card
    credit_card_number account_number routing_number sort_code tax_id
    national_id social_security_number pin_code authorization cookie bearer
  )

  @doc """
  Resolves the effective policy once.

  Options:

    * `:policy` - an already-resolved `Chronicle.Redaction.Policy`
    * `:schema` - an Ecto schema whose `Chronicle.Schema` policy contributes
    * `:redact` - extra fields to redact for this call
  """
  @spec compile(keyword()) :: Policy.t()
  def compile(opts \\ [])

  def compile(%Policy{} = policy), do: policy

  def compile(opts) when is_list(opts) do
    case Keyword.get(opts, :policy) do
      %Policy{} = policy ->
        policy

      _other ->
        configured = Chronicle.Config.get_env(:redaction, [])
        schema = Keyword.get(opts, :schema)
        local = schema_policy(schema)

        %Policy{
          builtin?: Keyword.get(configured, :builtin, true),
          redact:
            name_set([Keyword.get(configured, :fields, []), local.redact, call_fields(opts)]),
          hash: name_set([Keyword.get(configured, :hash_fields, []), local.hash]),
          omit: name_set([Keyword.get(configured, :omit_fields, []), local.omit])
        }
    end
  end

  @doc """
  Applies the policy to one field, returning the value or a `Sensitive` marker.
  """
  @spec protect_field(Policy.t(), term(), term()) :: term()
  def protect_field(%Policy{} = policy, field, value) do
    name = field_name(field)

    cond do
      MapSet.member?(policy.omit, name) -> %Sensitive{strategy: :omit}
      MapSet.member?(policy.hash, name) -> %Sensitive{strategy: :hash, value: value}
      MapSet.member?(policy.redact, name) -> %Sensitive{strategy: :redact, value: value}
      policy.builtin? and builtin?(name) -> %Sensitive{strategy: :redact, value: value}
      true -> value
    end
  end

  @doc """
  Returns whether a field name is protected by the built-in rules.
  """
  @spec builtin?(String.t()) :: boolean()
  def builtin?(name) when is_binary(name) do
    downcased = String.downcase(name)

    downcased in @names or
      Enum.any?(@substrings, &String.contains?(downcased, &1)) or
      Enum.any?(String.split(downcased, "_"), &(&1 in @segments))
  end

  @doc """
  Returns the protected fields of an Ecto schema, for diagnostics.
  """
  @spec protected_fields(module(), keyword()) :: [atom()]
  def protected_fields(schema, opts \\ []) when is_atom(schema) do
    if function_exported?(schema, :__schema__, 1) do
      policy = compile(Keyword.put(opts, :schema, schema))
      erasable = schema |> schema_policy() |> Map.get(:erasable, []) |> Keyword.keys()

      Enum.filter(schema.__schema__(:fields), fn field ->
        field not in erasable and match?(%Sensitive{}, protect_field(policy, field, nil))
      end)
    else
      []
    end
  end

  @doc """
  Builds the field redactor used for Ecto changes and snapshots.
  """
  @spec ecto_redactor(module() | nil, keyword()) :: (atom(), term() -> term())
  def ecto_redactor(schema, opts) do
    case Keyword.get(opts, :redact) do
      function when is_function(function, 2) ->
        function

      fields when is_list(fields) or is_nil(fields) ->
        policy = compile(Keyword.put(opts, :schema, schema))
        erasable = schema |> schema_policy() |> Map.get(:erasable, [])
        record = Keyword.get(opts, :record)

        fn field, value ->
          case Keyword.fetch(erasable, field) do
            {:ok, key_field} ->
              %Erasable{value: value, key_id: erasure_key_id!(record, schema, key_field)}

            :error ->
              protect_field(policy, field, value)
          end
        end

      other ->
        raise ArgumentError,
              ":redact must be a list or a two-argument function, got: #{inspect(other)}"
    end
  end

  defp call_fields(opts) do
    case Keyword.get(opts, :redact) do
      fields when is_list(fields) -> fields
      _other -> []
    end
  end

  defp name_set(lists) do
    lists
    |> Enum.concat()
    |> Enum.map(&field_name/1)
    |> MapSet.new()
  end

  defp field_name(field) when is_binary(field), do: field
  defp field_name(field) when is_atom(field), do: Atom.to_string(field)
  defp field_name(field), do: to_string(field)

  defp erasure_key_id!(%{} = record, schema, key_field) do
    case Map.get(record, key_field) do
      key_id when is_binary(key_id) and byte_size(key_id) > 0 ->
        key_id

      value ->
        raise ArgumentError,
              "#{inspect(schema)} erasable field requires #{inspect(key_field)} " <>
                "to contain a non-empty key id, got: #{inspect(value)}"
    end
  end

  defp erasure_key_id!(_record, schema, key_field) do
    raise ArgumentError,
          "#{inspect(schema)} erasable field requires a record to resolve " <>
            "#{inspect(key_field)}"
  end

  defp schema_policy(nil), do: %{redact: [], hash: [], omit: [], erasable: []}

  defp schema_policy(schema) do
    if Code.ensure_loaded?(Chronicle.Ecto.Policy) do
      schema |> Chronicle.Ecto.Policy.get() |> Map.take([:redact, :hash, :omit, :erasable])
    else
      %{redact: [], hash: [], omit: [], erasable: []}
    end
  end
end
