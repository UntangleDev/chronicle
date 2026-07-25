if Code.ensure_loaded?(Ecto.Schema) do
  defmodule Chronicle.Ecto.Policy do
    @moduledoc """
    Schema-local change selection and protection policy.

    The two settings answer different questions:

      * `only` and `except` select which field changes are worth reporting. An
        update touching only excluded fields records nothing at all.
      * `redact`, `hash`, and `omit` withhold a value from the audit store.
        A withheld field cannot be reconstructed, so versions containing one
        are reported incomplete.

    `hash` stores an unsalted SHA-256 fingerprint. It answers correlation
    questions — did this field change, did it revert, does it match another
    record — but it is not secrecy: a value drawn from a small or guessable
    set can be recovered by hashing candidates until one matches. Use `redact`
    or `omit` when the value itself must not be recoverable.

    Excluding a field from diffs does not withhold it: a version still captures
    every persisted field, so time travel keeps working. Use `omit` to keep a
    value out of the store entirely.

    Put the policy beside the schema it governs:

        defmodule MyApp.Account do
          use Ecto.Schema
          use Chronicle.Schema,
            only: [:email, :password_hash, :session_token],
            redact: [:password_hash],
            hash: [:email],
            omit: [:session_token]

          schema "accounts" do
            field :email, :string
            field :password_hash, :string
            field :session_token, :string
          end
        end

    `only: :all` is the default. `except` removes fields from that set.
    A field may have only one protection strategy. Options must be literals so
    invalid policy shapes fail during compilation, and field names are checked
    against the Ecto schema once the module has compiled.
    """

    @type t :: %{
            only: :all | [atom()],
            except: [atom()],
            redact: [atom()],
            hash: [atom()],
            omit: [atom()]
          }

    defmacro __using__(opts) do
      unless Macro.quoted_literal?(opts) and Keyword.keyword?(opts) do
        raise ArgumentError,
              "#{inspect(__CALLER__.module)} Chronicle.Ecto.Policy options must be a literal keyword list"
      end

      policy = build_policy!(opts, __CALLER__.module)

      quote do
        @doc false
        def __audit_policy__, do: unquote(Macro.escape(policy))

        @after_compile Chronicle.Ecto.Policy
      end
    end

    @doc false
    def __after_compile__(env, _bytecode),
      do: validate_schema_fields!(env.module, env.module.__audit_policy__())

    @spec get(module() | nil) :: t()
    def get(nil), do: defaults()

    def get(schema) when is_atom(schema) do
      if function_exported?(schema, :__audit_policy__, 0) do
        schema.__audit_policy__()
      else
        defaults()
      end
    end

    @spec tracked?(t(), atom()) :: boolean()
    def tracked?(policy, field) do
      selected? = policy.only == :all or field in policy.only
      selected? and field not in policy.except
    end

    defp defaults do
      %{only: :all, except: [], redact: [], hash: [], omit: []}
    end

    defp build_policy!(opts, module) do
      allowed = Map.keys(defaults())
      unknown = Keyword.keys(opts) -- allowed

      if unknown != [] do
        raise ArgumentError,
              "#{inspect(module)} Chronicle.Ecto.Policy has unknown options: #{inspect(unknown)}"
      end

      policy =
        defaults()
        |> Map.merge(Map.new(opts))

      validate_shape!(policy, module)
      policy
    end

    defp validate_shape!(policy, module) do
      Enum.each([:except, :redact, :hash, :omit], fn key ->
        unless atom_list?(Map.fetch!(policy, key)) do
          raise ArgumentError,
                "#{inspect(module)} audit #{key} must be a list of field atoms"
        end
      end)

      unless policy.only == :all or atom_list?(policy.only) do
        raise ArgumentError,
              "#{inspect(module)} audit only must be :all or a list of field atoms"
      end

      protected = policy.redact ++ policy.hash ++ policy.omit

      if length(protected) != MapSet.size(MapSet.new(protected)) do
        raise ArgumentError,
              "#{inspect(module)} audit fields cannot use more than one protection strategy"
      end
    end

    defp validate_schema_fields!(schema, policy) do
      if function_exported?(schema, :__schema__, 1) do
        declared = MapSet.new(schema.__schema__(:fields))

        configured =
          List.wrap(if(policy.only == :all, do: [], else: policy.only)) ++
            policy.except ++ policy.redact ++ policy.hash ++ policy.omit

        unknown = configured |> MapSet.new() |> MapSet.difference(declared) |> MapSet.to_list()

        if unknown != [] do
          raise ArgumentError,
                "#{inspect(schema)} audit policy refers to unknown fields: #{inspect(unknown)}"
        end
      end

      policy
    end

    defp atom_list?(value), do: is_list(value) and Enum.all?(value, &is_atom/1)
  end
end

if Code.ensure_loaded?(Ecto.Schema) do
  defmodule Chronicle.Schema do
    @moduledoc """
    Optional audit policy for an Ecto schema.

    No declaration is required for the default: all persisted fields are
    captured, while common credential fields are protected.

    `only` and `except` narrow which changes are reported; `redact`, `hash`,
    and `omit` withhold a value and therefore make versions containing it
    non-restorable. See `Chronicle.Ecto.Policy` for the full contract.
    """

    defmacro __using__(opts) do
      quote do
        use Chronicle.Ecto.Policy, unquote(opts)
      end
    end
  end
end
