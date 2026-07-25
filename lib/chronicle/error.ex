defmodule Chronicle.Error do
  @moduledoc """
  Stable, structured error returned by the ergonomic audit APIs.

  Two audiences, two fields, and they are not interchangeable. `reason` is for
  code: a matchable term that callers pattern match on, and therefore API —
  changing one is a breaking change even though nothing in a type signature
  says so. `message` is for people, and is free to be reworded whenever it
  reads badly.

  `cause` and `stacktrace` carry the original failure rather than replacing it.
  An error that flattens its cause into a sentence has destroyed the only thing
  that would have explained it, and the operator reading the log at three in
  the morning cannot get it back.

  `retryable?` is a claim about the failure, not a suggestion about what to do.
  A signing key that cannot be resolved will not resolve itself on the second
  attempt; a lock timeout might.
  """

  defexception [
    :message,
    :operation,
    :store,
    :reason,
    :cause,
    :stacktrace,
    retryable?: false
  ]

  @type t :: %__MODULE__{
          message: String.t(),
          operation: atom(),
          store: atom() | nil,
          reason: atom() | term(),
          cause: term(),
          stacktrace: list() | nil,
          retryable?: boolean()
        }

  @spec new(atom(), term(), keyword()) :: t()
  def new(operation, reason, opts \\ []) do
    {stable_reason, cause, stacktrace} = normalize_reason(reason)
    store = Keyword.get(opts, :store)

    %__MODULE__{
      operation: operation,
      store: store,
      reason: stable_reason,
      cause: cause,
      stacktrace: stacktrace,
      retryable?: retryable?(stable_reason, cause),
      message: message(operation, store, stable_reason)
    }
  end

  @spec wrap(atom(), term(), keyword()) :: t()
  def wrap(operation, reason, opts \\ [])
  def wrap(_operation, %__MODULE__{} = error, _opts), do: error
  def wrap(operation, reason, opts), do: new(operation, reason, opts)

  defp normalize_reason(:provider_not_configured),
    do: {:store_not_configured, :provider_not_configured, nil}

  defp normalize_reason({:store_not_configured, _name} = cause),
    do: {:store_not_configured, cause, nil}

  defp normalize_reason({:store_provider_missing, _name} = cause),
    do: {:store_not_configured, cause, nil}

  defp normalize_reason(:integrity_key_not_configured),
    do: {:integrity_key_missing, :integrity_key_not_configured, nil}

  defp normalize_reason({:integrity_key_too_short, _, _} = cause),
    do: {:integrity_key_too_short, cause, nil}

  defp normalize_reason({:checkpoint_mismatch, _} = cause),
    do: {:checkpoint_mismatch, cause, nil}

  defp normalize_reason({:checkpoint_ledgers_missing, _} = cause),
    do: {:checkpoint_mismatch, cause, nil}

  defp normalize_reason({:snapshot_incomplete, _fields} = cause),
    do: {:snapshot_incomplete, cause, nil}

  defp normalize_reason({:schema_incompatible, _stored, _current} = cause),
    do: {:schema_incompatible, cause, nil}

  defp normalize_reason({:version_not_found, _version} = cause),
    do: {:version_not_found, cause, nil}

  defp normalize_reason({:version_event_not_found, _event_id} = cause),
    do: {:version_not_found, cause, nil}

  defp normalize_reason({operation, _reason} = cause)
       when operation in [:checkpoint_load_failed, :checkpoint_save_failed],
       do: {:checkpoint_store_failure, cause, nil}

  defp normalize_reason({:ledger_verification_failed, _ledger, reason} = cause),
    do: {verification_reason(reason), cause, nil}

  defp normalize_reason({:content_digest_mismatch, _} = cause),
    do: {:content_tampered, cause, nil}

  defp normalize_reason({reason, _detail} = cause)
       when reason in [
              :previous_digest_mismatch,
              :chain_digest_mismatch,
              :signature_mismatch,
              :ledger_head_mismatch,
              :ledger_coverage_mismatch
            ],
       do: {:ledger_tampered, cause, nil}

  defp normalize_reason({:ledger_head_mismatch, _stored, _computed} = cause),
    do: {:ledger_tampered, cause, nil}

  defp normalize_reason({:unexpected_sequence, _} = cause),
    do: {:sequence_gap, cause, nil}

  defp normalize_reason(:unsigned_audit_records_present),
    do: {:unsigned_records_present, :unsigned_audit_records_present, nil}

  defp normalize_reason({:ecto_store_required, _name} = cause),
    do: {:ecto_store_required, cause, nil}

  defp normalize_reason({:repo_not_configured, _name} = cause),
    do: {:repo_not_configured, cause, nil}

  defp normalize_reason({reason, _name} = cause)
       when reason in [:invalid_provider, :invalid_store_configuration],
       do: {:store_not_configured, cause, nil}

  defp normalize_reason({:invalid_store_configuration, _name, _config} = cause),
    do: {:store_not_configured, cause, nil}

  # Signing-key configuration: the ledger cannot choose a key for this write.
  defp normalize_reason({reason, _detail} = cause)
       when reason in [
              :no_signing_key_for_sequence,
              :key_epoch_not_found,
              :invalid_key_epoch,
              :keyring_failure,
              :invalid_keyring_result
            ],
       do: {:signing_key_invalid, cause, nil}

  defp normalize_reason({:overlapping_key_epochs, _sequence, _ids} = cause),
    do: {:signing_key_invalid, cause, nil}

  defp normalize_reason({:key_not_valid_at_sequence, _id, _sequence, _epoch} = cause),
    do: {:signing_key_invalid, cause, nil}

  defp normalize_reason({:key_id_mismatch, _expected, _actual} = cause),
    do: {:signing_key_invalid, cause, nil}

  defp normalize_reason({:verification_key_not_found, _key_id} = cause),
    do: {:verification_key_missing, cause, nil}

  defp normalize_reason({:invalid_integrity_option, _field, _value} = cause),
    do: {:integrity_misconfigured, cause, nil}

  defp normalize_reason({:invalid_integrity_key_source, _source} = cause),
    do: {:integrity_key_missing, cause, nil}

  defp normalize_reason({reason, _detail} = cause)
       when reason in [:invalid_base64_integrity_key, :environment_variable_not_set],
       do: {:integrity_key_missing, cause, nil}

  # Caller-supplied query, page, or version selector is not usable.
  defp normalize_reason(:invalid_audit_cursor),
    do: {:invalid_query, :invalid_audit_cursor, nil}

  defp normalize_reason({reason, _detail} = cause)
       when reason in [
              :invalid_query_filter,
              :conflicting_version_selectors,
              :invalid_version_selector,
              :ecto_query_not_supported,
              :ecto_query_not_available
            ],
       do: {:invalid_query, cause, nil}

  defp normalize_reason({reason, _a, _b} = cause)
       when reason in [:invalid_query_option, :invalid_history_page, :cursor_ledger_mismatch],
       do: {:invalid_query, cause, nil}

  # The requested record or version does not exist.
  defp normalize_reason({reason, _detail} = cause)
       when reason in [:record_state_not_found, :invalid_version_event, :audit_group_not_found],
       do: {:version_not_found, cause, nil}

  defp normalize_reason({:invalid_version_event, _id, _reason} = cause),
    do: {:version_not_found, cause, nil}

  defp normalize_reason(reason) when reason in [:record_history_not_found, :record_deleted],
    do: {reason, reason, nil}

  # Ledger bookkeeping failed while writing.
  defp normalize_reason(:ledger_head_missing),
    do: {:ledger_write_failed, :ledger_head_missing, nil}

  defp normalize_reason({reason, _result} = cause)
       when reason in [
              :unexpected_insert_result,
              :unexpected_group_insert_result,
              :unexpected_event_insert_result,
              :unexpected_ledger_insert_result,
              :unexpected_ledger_head_insert_result,
              :unexpected_ledger_head_update_result
            ],
       do: {:ledger_write_failed, cause, nil}

  defp normalize_reason({:transaction_failed, _operation, _reason} = cause),
    do: {:transaction_failed, cause, nil}

  defp normalize_reason({:ecto, exception, stacktrace}),
    do: {ecto_reason(exception), exception, stacktrace}

  defp normalize_reason({reason, exception, stacktrace})
       when reason in [:provider_exception, :reader_exception, :ecto_query, :ecto_history] and
              is_list(stacktrace),
       do: {:provider_failure, exception, stacktrace}

  defp normalize_reason(reason) when is_atom(reason), do: {reason, reason, nil}
  defp normalize_reason(reason), do: {:audit_failure, reason, nil}

  defp verification_reason({:content_digest_mismatch, _}), do: :content_tampered
  defp verification_reason({:checkpoint_mismatch, _}), do: :checkpoint_mismatch
  defp verification_reason({:verification_key_not_found, _}), do: :verification_key_missing

  defp verification_reason({reason, _detail})
       when reason in [
              :unexpected_sequence,
              :previous_digest_mismatch,
              :chain_digest_mismatch,
              :signature_mismatch,
              :ledger_head_mismatch,
              :ledger_coverage_mismatch
            ],
       do: :ledger_tampered

  defp verification_reason({:ledger_head_mismatch, _stored, _computed}), do: :ledger_tampered

  defp verification_reason(reason)
       when reason in [
              :duplicate_ledger_record_reference,
              :group_event_coverage_mismatch,
              :unsigned_audit_records_present
            ],
       do: :ledger_tampered

  # Reached only from the verify path, where the ledger name was discovered
  # because rows reference it. Rows with no head is a missing chain, not an
  # uninitialized store.
  defp verification_reason(:ledger_not_initialized), do: :ledger_tampered

  # A signed group covers an exact set of children; a changed count or a
  # missing record is tampering, not an unclassified failure.
  defp verification_reason({:group_event_count_mismatch, _id, _expected, _actual}),
    do: :ledger_tampered

  defp verification_reason({:audit_record_missing, _kind, _id}), do: :ledger_tampered

  defp verification_reason(_reason), do: :verification_failed

  defp ecto_reason(%ArgumentError{message: message}) do
    cond do
      message =~ "integrity option" -> :integrity_key_missing
      message =~ "requires the :integrity" -> :integrity_key_missing
      true -> :provider_failure
    end
  end

  defp ecto_reason(_exception), do: :provider_failure

  defp retryable?(reason, _cause) when reason in [:provider_unavailable, :ledger_lock_failed],
    do: true

  defp retryable?(:provider_failure, %{__struct__: module}) do
    module in [DBConnection.ConnectionError, DBConnection.OwnershipError]
  rescue
    UndefinedFunctionError -> false
  end

  defp retryable?(_reason, _cause), do: false

  defp message(operation, nil, reason), do: "audit #{operation} failed: #{inspect(reason)}"

  defp message(operation, store, reason),
    do: "audit #{operation} failed for store #{inspect(store)}: #{inspect(reason)}"
end
