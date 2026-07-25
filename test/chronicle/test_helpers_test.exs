defmodule Chronicle.TestHelpersTest do
  use ExUnit.Case, async: true

  use Chronicle

  test "captures audit calls through explicit options" do
    {result, entries} =
      Chronicle.Test.capture(fn audit_opts ->
        Chronicle.run("account.disable", audit_opts, fn ->
          Chronicle.record!(
            "authorization.allowed",
            %{policy: "admin"},
            audit_opts
          )

          :disabled
        end)
      end)

    assert result == :disabled
    assert Chronicle.Test.group?(entries, "account.disable", &(&1.outcome == :success))

    assert Chronicle.Test.event?(
             entries,
             "authorization.allowed",
             &(&1.data["policy"] == "admin")
           )
  end

  test "capture options work in spawned processes" do
    {_result, entries} =
      Chronicle.Test.capture(fn audit_opts ->
        Task.async(fn -> Chronicle.record!("job.started", %{}, audit_opts) end)
        |> Task.await()
      end)

    assert Chronicle.Test.event?(entries, "job.started")
  end
end
