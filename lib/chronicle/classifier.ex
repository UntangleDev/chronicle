defmodule Chronicle.Classifier do
  @moduledoc """
  Built-in result-to-audit-outcome classifiers.

  `:default` is used when a call does not set `:classify`. It records a
  failure when the callback returned `:error` or `{:error, reason}` and a
  success otherwise, so an audited operation is never recorded as successful
  merely because it did not raise.

  | Classifier | `:ok` / `{:ok, _}` | `:error` / `{:error, _}` | anything else |
  | --- | --- | --- | --- |
  | `:default` | success | failure | success |
  | `:result_tuple` | success | failure | unknown |
  | `:boolean` | `true` success | `false` failure | unknown |
  | `:http_status` | status < 400 | status >= 400 | unknown |
  | `:always_success` | success | success | success |

  A custom classifier is a one-argument function returning `:success`,
  `:failure`, `:unknown`, or a non-empty outcome string.

  `:unknown` is a real outcome rather than a gap to be filled in. A classifier
  that cannot tell what happened has two dishonest options and one honest one:
  recording success hides failures, recording failure invents them, and saying
  so leaves a record an investigator can act on. The stricter classifiers
  return it freely for that reason.
  """

  @type classifier ::
          :default
          | :always_success
          | :result_tuple
          | :boolean
          | :http_status
          | (term() -> Chronicle.Event.outcome())

  @builtin [:default, :always_success, :result_tuple, :boolean, :http_status]

  @spec classify(term(), classifier() | nil) :: Chronicle.Event.outcome()
  def classify(_result, nil), do: :success
  def classify(_result, :always_success), do: :success

  def classify(:error, :default), do: :failure
  def classify({:error, _reason}, :default), do: :failure
  def classify(_other, :default), do: :success

  def classify(:ok, :result_tuple), do: :success
  def classify({:ok, _value}, :result_tuple), do: :success
  def classify(:error, :result_tuple), do: :failure
  def classify({:error, _reason}, :result_tuple), do: :failure
  def classify(_other, :result_tuple), do: :unknown

  def classify(true, :boolean), do: :success
  def classify(false, :boolean), do: :failure
  def classify(_other, :boolean), do: :unknown

  def classify(status, :http_status) when is_integer(status) and status < 400, do: :success
  def classify(status, :http_status) when is_integer(status), do: :failure
  def classify(%{status: status}, :http_status), do: classify(status, :http_status)
  def classify(_other, :http_status), do: :unknown

  def classify(result, classifier) when is_function(classifier, 1), do: classifier.(result)

  def classify(_result, classifier) do
    raise ArgumentError,
          ":classify must be one of #{inspect(@builtin)} or a one-argument function, " <>
            "got: #{inspect(classifier)}"
  end
end
