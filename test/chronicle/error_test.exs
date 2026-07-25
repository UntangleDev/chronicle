defmodule Chronicle.ErrorTest do
  @moduledoc """
  `Chronicle.Error.reason` is API: callers pattern match on it. Every family
  below must stay matchable rather than collapsing into `:audit_failure`.
  """

  use ExUnit.Case, async: true

  alias Chronicle.Error

  defp reason(cause), do: Error.new(:write, cause).reason

  describe "store configuration" do
    test "names the specific problem" do
      assert reason({:store_not_configured, :primary}) == :store_not_configured
      assert reason({:store_provider_missing, :primary}) == :store_not_configured
      assert reason(:provider_not_configured) == :store_not_configured
      assert reason({:invalid_provider, :nope}) == :store_not_configured
      assert reason({:invalid_store_configuration, :primary, %{}}) == :store_not_configured
      assert reason({:ecto_store_required, :memory}) == :ecto_store_required
      assert reason({:repo_not_configured, :primary}) == :repo_not_configured
    end
  end

  describe "keys" do
    test "distinguishes a missing key from an unusable one" do
      assert reason(:integrity_key_not_configured) == :integrity_key_missing
      assert reason({:invalid_integrity_key_source, :nope}) == :integrity_key_missing
      assert reason({:invalid_base64_integrity_key, :inline}) == :integrity_key_missing
      assert reason({:environment_variable_not_set, "K"}) == :integrity_key_missing
      assert reason({:integrity_key_too_short, 8, 32}) == :integrity_key_too_short
      assert reason({:invalid_integrity_option, :ledger, ""}) == :integrity_misconfigured
    end

    test "signing-key selection failures are one family" do
      for cause <- [
            {:no_signing_key_for_sequence, 1},
            {:key_epoch_not_found, "k"},
            {:invalid_key_epoch, []},
            {:keyring_failure, %RuntimeError{}},
            {:invalid_keyring_result, :nope},
            {:overlapping_key_epochs, 3, ["a", "b"]},
            {:key_not_valid_at_sequence, "k", 3, {1, 2}},
            {:key_id_mismatch, "a", "b"}
          ] do
        assert reason(cause) == :signing_key_invalid, "for #{inspect(cause)}"
      end

      assert reason({:verification_key_not_found, "k"}) == :verification_key_missing
    end
  end

  describe "tampering" do
    test "content and chain damage are distinguishable" do
      assert reason({:content_digest_mismatch, 3}) == :content_tampered
      assert reason({:unexpected_sequence, 3}) == :sequence_gap
      assert reason(:unsigned_audit_records_present) == :unsigned_records_present

      for cause <- [
            {:previous_digest_mismatch, 1},
            {:chain_digest_mismatch, 1},
            {:signature_mismatch, 1},
            {:ledger_coverage_mismatch, %{}},
            {:ledger_head_mismatch, %{sequence: 1}, %{sequence: 2}}
          ] do
        assert reason(cause) == :ledger_tampered, "for #{inspect(cause)}"
      end
    end

    test "a verification failure is classified by its inner cause" do
      wrap = fn inner -> reason({:ledger_verification_failed, "primary", inner}) end

      assert wrap.({:content_digest_mismatch, 1}) == :content_tampered
      assert wrap.({:checkpoint_mismatch, %{}}) == :checkpoint_mismatch
      assert wrap.({:verification_key_not_found, "k"}) == :verification_key_missing
      assert wrap.({:signature_mismatch, 1}) == :ledger_tampered
      assert wrap.({:ledger_head_mismatch, %{}, %{}}) == :ledger_tampered
      assert wrap.(:ledger_not_initialized) == :ledger_tampered
      assert wrap.(:group_event_coverage_mismatch) == :ledger_tampered
      assert wrap.({:group_event_count_mismatch, "id", 2, 1}) == :ledger_tampered
      assert wrap.({:audit_record_missing, :event, "id"}) == :ledger_tampered
    end

    test "an unrecognised verification cause is not silently a success" do
      assert reason({:ledger_verification_failed, "primary", :something_new}) ==
               :verification_failed
    end
  end

  describe "checkpoints" do
    test "load, save, and mismatch are distinguishable" do
      assert reason({:checkpoint_mismatch, %{}}) == :checkpoint_mismatch
      assert reason({:checkpoint_ledgers_missing, ["a"]}) == :checkpoint_mismatch
      assert reason({:checkpoint_load_failed, :enoent}) == :checkpoint_store_failure
      assert reason({:checkpoint_save_failed, :eacces}) == :checkpoint_store_failure
    end
  end

  describe "reads" do
    test "a bad query is not reported as a store failure" do
      assert reason(:invalid_audit_cursor) == :invalid_query
      assert reason({:invalid_query_filter, :nope}) == :invalid_query
      assert reason({:invalid_version_selector, []}) == :invalid_query
      assert reason({:conflicting_version_selectors, [:at, :version]}) == :invalid_query
      assert reason({:ecto_query_not_supported, :memory}) == :invalid_query
      assert reason({:invalid_query_option, :limit, 0}) == :invalid_query
      assert reason({:invalid_history_page, 0, 0}) == :invalid_query
      assert reason({:cursor_ledger_mismatch, "a", "b"}) == :invalid_query
    end

    test "a missing record is distinguishable from a broken one" do
      assert reason({:version_not_found, 3}) == :version_not_found
      assert reason({:version_event_not_found, "id"}) == :version_not_found
      assert reason({:record_state_not_found, DateTime.utc_now()}) == :version_not_found
      assert reason({:invalid_version_event, "id"}) == :version_not_found
      assert reason({:invalid_version_event, "id", :bad}) == :version_not_found
      assert reason(:record_history_not_found) == :record_history_not_found
      assert reason(:record_deleted) == :record_deleted
      assert reason({:snapshot_incomplete, [:secret]}) == :snapshot_incomplete
      assert reason({:schema_incompatible, "a", "b"}) == :schema_incompatible
    end
  end

  describe "writes" do
    test "ledger bookkeeping failures are one family" do
      assert reason(:ledger_head_missing) == :ledger_write_failed

      for reason_tag <- [
            :unexpected_insert_result,
            :unexpected_group_insert_result,
            :unexpected_event_insert_result,
            :unexpected_ledger_insert_result,
            :unexpected_ledger_head_insert_result,
            :unexpected_ledger_head_update_result
          ] do
        assert reason({reason_tag, {0, nil}}) == :ledger_write_failed
      end

      assert reason({:transaction_failed, :step, :boom}) == :transaction_failed
    end

    test "provider exceptions keep their stacktrace" do
      stacktrace = [{Foo, :bar, 0, []}]
      error = Error.new(:write, {:provider_exception, %RuntimeError{}, stacktrace})

      assert error.reason == :provider_failure
      assert error.stacktrace == stacktrace
      assert %RuntimeError{} = error.cause
    end

    test "an Ecto ArgumentError about integrity is reported as a key problem" do
      cause = {:ecto, %ArgumentError{message: "requires the :integrity option"}, []}
      assert reason(cause) == :integrity_key_missing

      other = {:ecto, %ArgumentError{message: "something else"}, []}
      assert reason(other) == :provider_failure
    end
  end

  describe "shape" do
    test "an unknown cause is still an error, marked as unclassified" do
      assert reason({:brand_new_thing, 1, 2, 3}) == :audit_failure
      assert reason(:some_atom) == :some_atom
    end

    test "wrap/3 leaves an existing error untouched" do
      error = Error.new(:write, :boom, store: :primary)
      assert Error.wrap(:verify, error, store: :other) == error
    end

    test "the message names the operation and store" do
      assert Error.new(:verify, :boom, store: :primary).message =~
               "audit verify failed for store :primary"

      assert Error.new(:verify, :boom).message =~ "audit verify failed:"
    end

    test "connection failures are retryable and tampering is not" do
      assert Error.new(:write, :provider_unavailable).retryable?
      assert Error.new(:write, :ledger_lock_failed).retryable?
      refute Error.new(:verify, {:signature_mismatch, 1}).retryable?
      refute Error.new(:write, {:provider_exception, %RuntimeError{}, []}).retryable?
    end

    test "is a raisable exception" do
      assert_raise Chronicle.Error, ~r/audit write failed/, fn ->
        raise Error.new(:write, :boom)
      end
    end
  end

  test "Chronicle.IntegrityError carries its reason" do
    error = Chronicle.IntegrityError.exception({:signature_mismatch, 3})

    assert error.reason == {:signature_mismatch, 3}
    assert Exception.message(error) =~ "audit integrity verification failed"
  end
end
