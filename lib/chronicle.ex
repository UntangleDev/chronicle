defmodule Chronicle do
  @moduledoc """
  Tamper-evident audit facts and restorable Ecto record versions.

  Configure the common single-repository case:

      config :chronicle,
        repo: MyApp.Repo,
        signing_key: {:system, "CHRONICLE_SIGNING_KEY_BASE64", :base64}

  Ecto writes mirror `Ecto.Repo` and commit their audit version atomically:

      Chronicle.insert(changeset, actor: current_user)
      Chronicle.update(changeset, actor: current_user)
      Chronicle.delete(record, actor: current_user)

  Read or reconstruct record history:

      Chronicle.history(record)
      Chronicle.at(record, version: 3)
      Chronicle.revert(record, version: 3)

  `record/3` captures facts that are not database mutations, while
  `transaction/3` groups related Ecto writes and arbitrary facts into one
  signed unit.

  ## Block syntax

  Every construct that wraps a section of your code takes a `do` block:
  `transaction/3`, `span/3`, `run/3`, `group/3`,
  `Chronicle.Phoenix.with_context/3`, `Chronicle.Phoenix.run/4`, and
  `Chronicle.Oban.with_context/2`. They are macros, so `use Chronicle` once per
  calling module — the same arrangement as `Logger`:

      defmodule MyApp.Orders do
        use Chronicle

        def checkout(user, order) do
          Chronicle.transaction "order.checkout", actor: user do
            Chronicle.record!("payment.captured", %{order_id: order.id})
          end
        end
      end

  One `use Chronicle` covers the optional Phoenix and Oban integrations too,
  when those dependencies are present. Every construct also accepts an explicit
  zero-arity function in the same position, so existing function-form calls
  keep working:

      Chronicle.transaction("order.checkout", [actor: user], fn -> ... end)

  ## Why the block forms are macros

  `do`/`end` is syntax, not a value. A function cannot receive a block, so
  every construct that reads as `Chronicle.transaction "type" do ... end` has to
  be a macro — and macros must be required before use, exactly as `Logger` is.
  That is the only reason `use Chronicle` exists; it requires this module and
  whichever optional integrations are present, and does nothing else.

  The consequence worth knowing is the failure mode. Calling a block form
  without requiring the module does not produce a helpful "you must require"
  message: Elixir parses the block into a keyword list with a `:do` key, finds
  no matching function head, and raises `FunctionClauseError` from somewhere
  that looks unrelated. If a block form fails that way, the missing `require`
  is the first thing to check.

  Both forms exist because the block reads better in application code and the
  function form composes better when the callback is already a value. They
  route to the same implementation — `__split_block__/3` decides which one it
  was handed — so there is one behaviour and one place to change it.
  """

  alias Chronicle.{Config, Error, Event, Store}

  @type audit_options :: keyword()
  @type outcome :: Chronicle.Event.outcome()

  @doc """
  Requires `Chronicle` so its block-form macros can be used.
  """
  defmacro __using__(_opts) do
    # One `use Chronicle` unlocks every block-form construct that is available,
    # including the optional Phoenix and Oban integrations.
    requires =
      for module <- [Chronicle, Chronicle.Phoenix, Chronicle.Oban],
          Code.ensure_loaded?(module) do
        quote(do: require(unquote(module)))
      end

    quote(do: (unquote_splicing(requires)))
  end

  # ----------------------------------------------------------------------
  # Ecto writes
  # ----------------------------------------------------------------------

  @doc """
  Inserts an Ecto changeset and its signed version in one transaction.

  Returns `{:error, changeset}` for invalid domain changes and
  `{:error, %Chronicle.Error{}}` when the audit write fails, in which case the
  domain mutation is rolled back.
  """
  @spec insert(Ecto.Changeset.t(), audit_options()) ::
          {:ok, struct()} | {:error, Ecto.Changeset.t() | Error.t()}
  def insert(changeset, opts \\ []) when is_list(opts),
    do: Chronicle.Ecto.Repo.insert(changeset, opts)

  @doc "Raising variant of `insert/2`."
  @spec insert!(Ecto.Changeset.t(), audit_options()) :: struct()
  def insert!(changeset, opts \\ []) when is_list(opts),
    do: Chronicle.Ecto.Repo.insert!(changeset, opts)

  @doc """
  Updates an Ecto changeset and records its signed version atomically.
  """
  @spec update(Ecto.Changeset.t(), audit_options()) ::
          {:ok, struct()} | {:error, Ecto.Changeset.t() | Error.t()}
  def update(changeset, opts \\ []) when is_list(opts),
    do: Chronicle.Ecto.Repo.update(changeset, opts)

  @doc "Raising variant of `update/2`."
  @spec update!(Ecto.Changeset.t(), audit_options()) :: struct()
  def update!(changeset, opts \\ []) when is_list(opts),
    do: Chronicle.Ecto.Repo.update!(changeset, opts)

  @doc """
  Deletes an Ecto record and records a signed tombstone atomically.
  """
  @spec delete(Ecto.Changeset.t() | struct(), audit_options()) ::
          {:ok, struct()} | {:error, Ecto.Changeset.t() | Error.t()}
  def delete(changeset_or_struct, opts \\ []) when is_list(opts),
    do: Chronicle.Ecto.Repo.delete(changeset_or_struct, opts)

  @doc "Raising variant of `delete/2`."
  @spec delete!(Ecto.Changeset.t() | struct(), audit_options()) :: struct()
  def delete!(changeset_or_struct, opts \\ []) when is_list(opts),
    do: Chronicle.Ecto.Repo.delete!(changeset_or_struct, opts)

  @doc """
  Runs domain changes and all nested audit facts as one signed group in the
  configured repository transaction.

  Takes a `do` block or a zero-arity function:

      Chronicle.transaction "order.checkout", actor: user do
        Chronicle.update!(changeset)
      end

  The block's value is the transaction result. By default the outcome is a
  failure only when the block returns `:error` or `{:error, reason}`; pass
  `:classify` to change that.
  """
  defmacro transaction(type, opts \\ [], fun \\ nil) do
    {opts, fun} = split_callback!(opts, fun, "Chronicle.transaction")

    quote do
      Chronicle.Ecto.Repo.transaction(unquote(type), unquote(opts), unquote(fun))
    end
  end

  # ----------------------------------------------------------------------
  # Record history
  # ----------------------------------------------------------------------

  @doc """
  Returns signed versions for an Ecto record, newest first.

  Accepts a loaded struct, or a schema module plus a primary key. Composite
  primary keys take a map or keyword list. Defaults to 50 entries; `:limit`
  and `:offset` page through older versions.
  """
  @spec history(struct() | module(), audit_options() | term()) ::
          {:ok, [Chronicle.Version.t()]} | {:error, Error.t()}
  def history(record_or_schema, opts_or_id \\ [])

  def history(%_{} = record, opts) when is_list(opts),
    do: Chronicle.Ecto.Repo.history(record, opts)

  def history(schema, id) when is_atom(schema),
    do: Chronicle.Ecto.Repo.history(schema, id, [])

  @spec history(module(), term(), audit_options()) ::
          {:ok, [Chronicle.Version.t()]} | {:error, Error.t()}
  def history(schema, id, opts) when is_atom(schema) and is_list(opts),
    do: Chronicle.Ecto.Repo.history(schema, id, opts)

  @doc """
  Reconstructs an Ecto record at a version, event, timestamp, or its latest
  audited state.

  Fails with `:snapshot_incomplete` rather than inventing values when the
  version omits protected fields, and with `:record_deleted` for a tombstone.
  """
  @spec at(struct() | module(), audit_options() | term()) ::
          {:ok, struct()} | {:error, Error.t()}
  def at(record_or_schema, opts_or_id \\ [])

  def at(%_{} = record, opts) when is_list(opts), do: Chronicle.Ecto.Repo.at(record, opts)
  def at(schema, id) when is_atom(schema), do: Chronicle.Ecto.Repo.at(schema, id, [])

  @spec at(module(), term(), audit_options()) :: {:ok, struct()} | {:error, Error.t()}
  def at(schema, id, opts) when is_atom(schema) and is_list(opts),
    do: Chronicle.Ecto.Repo.at(schema, id, opts)

  @doc """
  Returns a changeset that transitions the current record to a historical
  version. It never persists the change.
  """
  @spec revert(struct(), audit_options()) :: {:ok, Ecto.Changeset.t()} | {:error, Error.t()}
  def revert(record, opts) when is_struct(record) and is_list(opts),
    do: Chronicle.Ecto.Repo.revert(record, opts)

  # ----------------------------------------------------------------------
  # Arbitrary facts
  # ----------------------------------------------------------------------

  @doc """
  Records one audit fact.

  Data is a map; options are a keyword list. Unknown option keys raise, so a
  keyword list passed where data was intended is reported rather than silently
  dropped.
  """
  @spec record(String.t(), map() | audit_options()) :: {:ok, Event.t()} | {:error, Error.t()}
  def record(type, data_or_opts \\ %{})

  def record(type, opts) when is_list(opts), do: record(type, %{}, opts)
  def record(type, data) when is_map(data), do: record(type, data, [])

  @spec record(String.t(), map(), audit_options()) :: {:ok, Event.t()} | {:error, Error.t()}
  def record("chronicle.key_transition", _data, opts) do
    {:error, Error.new(:write, :reserved_audit_event_type, store: Config.store_name(opts))}
  end

  def record(type, data, opts) when is_map(data) and is_list(opts) do
    type
    |> Event.new(data, opts)
    |> persist(opts)
  end

  @doc "Raising variant of `record/3`."
  @spec record!(String.t(), map() | audit_options()) :: Event.t()
  def record!(type, data_or_opts \\ %{})

  def record!(type, opts) when is_list(opts), do: record!(type, %{}, opts)
  def record!(type, data) when is_map(data), do: record!(type, data, [])

  @spec record!(String.t(), map(), audit_options()) :: Event.t()
  def record!(type, data, opts) when is_map(data) and is_list(opts) do
    case record(type, data, opts) do
      {:ok, event} -> event
      {:error, %Error{} = error} -> raise error
    end
  end

  @doc """
  Persists or buffers a pre-built event.

  Set `immediate: true` to bypass an active group. This is primarily intended
  for transactional adapters such as `Chronicle.Multi`.
  """
  @spec persist(Event.t(), audit_options()) :: {:ok, Event.t()} | {:error, Error.t()}
  def persist(%Event{} = event, opts \\ []) when is_list(opts) do
    case {Chronicle.Context.current_group(), Keyword.get(opts, :immediate, false)} do
      {buffer, false} when is_pid(buffer) ->
        case Chronicle.Group.Buffer.append(buffer, event) do
          {:ok, grouped} = ok ->
            Chronicle.Scope.telemetry([:chronicle, :event, :buffered], %{count: 1}, %{
              event: grouped
            })

            ok

          {:error, reason} ->
            {:error, Error.wrap(:buffer, reason, store: Config.store_name(opts))}
        end

      _not_buffered ->
        case Chronicle.Provider.write_event(event, opts) do
          :ok -> written(event)
          {:ok, _provider_value} -> written(event)
          {:error, reason} -> {:error, Error.wrap(:write, reason, store: Config.store_name(opts))}
        end
    end
  end

  @doc """
  Records one timed operation and its outcome.

  Takes a `do` block or a zero-arity function. The callback's value is
  returned unchanged; an exception is recorded as a failure and re-raised.

      Chronicle.span "payment.authorize", subject: order do
        Payments.authorize(order)
      end
  """
  defmacro span(type, opts \\ [], fun \\ nil) do
    {opts, fun} = split_callback!(opts, fun, "Chronicle.span")

    quote do
      Chronicle.Scope.span(unquote(type), unquote(opts), unquote(fun))
    end
  end

  @doc """
  Executes one durable grouped unit, establishing context from its options.

  The lower-level primitive behind `transaction/3`, for non-Ecto providers.
  Takes a `do` block or a zero-arity function.
  """
  defmacro run(type, opts \\ [], fun \\ nil) do
    {opts, fun} = __split_block__(opts, fun, "Chronicle.run")
    quote(do: Chronicle.Scope.run(unquote(type), unquote(opts), unquote(fun)))
  end

  @doc """
  Executes one grouped unit without establishing context.

  Takes a `do` block or a zero-arity function.
  """
  defmacro group(type, opts \\ [], fun \\ nil) do
    {opts, fun} = __split_block__(opts, fun, "Chronicle.group")
    quote(do: Chronicle.Scope.group(unquote(type), unquote(opts), unquote(fun)))
  end

  # ----------------------------------------------------------------------
  # References and sensitive values
  # ----------------------------------------------------------------------

  @doc "Creates a stable audit reference from a value implementing `Chronicle.Identity`."
  @spec ref(term()) :: map() | nil
  def ref(value), do: Chronicle.Reference.resolve(value)

  @doc "Creates a stable audit reference from an explicit type and identifier."
  @spec ref(String.t() | atom(), term()) :: map()
  def ref(type, id), do: %{"type" => to_string(type), "id" => Chronicle.Value.normalize(id)}

  @doc "Alias of `ref/2`, for readability at actor call sites."
  @spec actor(String.t() | atom(), term()) :: map()
  def actor(type, id), do: ref(type, id)

  @doc ~s(Marks a value to be stored as `"[REDACTED]"`.)
  @spec secret(term()) :: Chronicle.Sensitive.t()
  def secret(value), do: %Chronicle.Sensitive{strategy: :redact, value: value}

  @doc """
  Marks a value to be stored as a deterministic SHA-256 fingerprint.

  A fingerprint answers correlation questions — did this field change, did it
  revert to an earlier value, does it match another record — without storing
  the value.

  It is not secrecy. The digest is unsalted, so any value drawn from a small or
  guessable set (an email address, a phone number, a postcode, a status, a
  short numeric code) can be recovered by hashing candidates until one matches.
  Use `secret/1` or `omit/0` when the value itself must not be recoverable.
  """
  @spec hash(term()) :: Chronicle.Sensitive.t()
  def hash(value), do: %Chronicle.Sensitive{strategy: :hash, value: value}

  @doc "Marks a map field or list item to be dropped entirely."
  @spec omit() :: Chronicle.Sensitive.t()
  def omit, do: %Chronicle.Sensitive{strategy: :omit}

  # ----------------------------------------------------------------------
  # Verification and operations
  # ----------------------------------------------------------------------

  @doc """
  Verifies the configured ledger of a named store.
  """
  @spec verify(atom(), keyword()) ::
          {:ok, Chronicle.Integrity.Checkpoint.t()} | {:error, Error.t()}
  def verify(store \\ Config.default_store(), opts \\ []),
    do: ledger_call(:verify, :verify, store, opts)

  @doc """
  Verifies every ledger in a named store, including unsigned-row coverage.
  """
  @spec verify_all(atom(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def verify_all(store \\ Config.default_store(), opts \\ []),
    do: ledger_call(:verify, :verify_all, store, opts)

  @doc """
  Reads the current unverified ledger head. This does not establish integrity.
  """
  @spec checkpoint(atom(), keyword()) ::
          {:ok, Chronicle.Integrity.Checkpoint.t()} | {:error, Error.t()}
  def checkpoint(store \\ Config.default_store(), opts \\ []),
    do: ledger_call(:checkpoint, :checkpoint, store, opts)

  @doc "Returns signing-key inventory and availability for a named store."
  @spec keys(atom()) :: {:ok, map()} | {:error, Error.t()}
  def keys(store \\ Config.default_store()), do: Chronicle.Keys.status(store)

  @doc """
  Checks signing keys, background-verifier status, and external anchor lag
  without performing a complete verification.
  """
  @spec health(atom(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def health(store \\ Config.default_store(), opts \\ []), do: Chronicle.Health.check(store, opts)

  # ----------------------------------------------------------------------
  # Internals
  # ----------------------------------------------------------------------

  defp written(event) do
    Chronicle.Scope.telemetry([:chronicle, :event, :written], %{count: 1}, %{event: event})
    {:ok, event}
  end

  defp ledger_call(operation, function, store, opts) do
    with {:ok, config} <- Config.fetch_store(store),
         {:ok, repo} <- ecto_repo(config),
         {:ok, result} <-
           apply(Chronicle.Ecto.Integrity, function, [
             repo,
             Keyword.merge(config.options, opts)
           ]) do
      {:ok, result}
    else
      {:error, reason} -> {:error, Error.wrap(operation, reason, store: store)}
    end
  rescue
    exception ->
      {:error,
       Error.new(operation, {:provider_exception, exception, __STACKTRACE__}, store: store)}
  end

  defp ecto_repo(%Store{provider: Chronicle.Provider.Ecto, name: name, options: options}) do
    cond do
      not Code.ensure_loaded?(Chronicle.Ecto.Integrity) -> {:error, :ecto_not_available}
      is_nil(options[:repo]) -> {:error, {:repo_not_configured, name}}
      true -> {:ok, options[:repo]}
    end
  end

  defp ecto_repo(%Store{name: name}), do: {:error, {:ecto_store_required, name}}

  @doc false
  # Splits `do` blocks out of the option list so the block-form and
  # function-form call shapes expand to the same runtime call. Public so the
  # optional Phoenix and Oban integrations expand identically.
  @spec __split_block__(Macro.t(), Macro.t() | nil, String.t()) :: {Macro.t(), Macro.t()}
  def __split_block__(opts, fun, name), do: split_callback!(opts, fun, name)

  defp split_callback!(opts, nil, _name) do
    case pop_block(opts) do
      {:ok, block, rest} -> {rest, wrap(block)}
      :error -> {[], opts}
    end
  end

  defp split_callback!(opts, fun, name) do
    case pop_block(fun) do
      {:ok, block, []} ->
        {opts, wrap(block)}

      {:ok, _block, [{key, _} | _]} ->
        raise ArgumentError,
              "#{name} received unexpected options after its block: #{inspect(key)}"

      :error ->
        {opts, fun}
    end
  end

  defp pop_block(ast) when is_list(ast) do
    if Keyword.keyword?(ast) do
      case Keyword.pop(ast, :do) do
        {nil, _rest} -> :error
        {block, rest} -> {:ok, block, rest}
      end
    else
      :error
    end
  end

  defp pop_block(_ast), do: :error

  defp wrap(block), do: quote(do: fn -> unquote(block) end)
end
