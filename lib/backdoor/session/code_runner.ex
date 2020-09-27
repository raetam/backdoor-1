defmodule Backdoor.Session.CodeRunner do
  use GenServer
  import Backdoor.Session.ViaTuple

  # Public API

  def start_link([session_id, name: name]) do
    GenServer.start_link(__MODULE__, session_id, name: name)
  end

  # Callbacks

  @impl true
  def init(session_id) do
    {:ok, %{session_id: session_id, bindings: [], env: init_env()}}
  end

  @impl true
  def handle_call({:execute, code}, {from, _ref}, state) do
    Backdoor.Session.CaptureOutput.set_as_group_leader(from, state.session_id)

    try do
      log(state.session_id, {:input, code})
      {result, bindings, env} = do_execute(code, state.bindings, state.env)
      log(state.session_id, {:result, result})
      {:reply, [{:input, code}, {:result, result}], %{state | bindings: bindings, env: env}}
    catch
      kind, error ->
        log(state.session_id, {:error, kind, error, __STACKTRACE__})
        {:reply, [{:input, code}, {:error, kind, error, __STACKTRACE__}], state}
    end
  end

  # private

  defp do_execute(code, bindings, env) do
    {:ok, ast} = Code.string_to_quoted(code)
    :elixir.eval_forms(ast, bindings, env)
  end

  defp init_env do
    :elixir.env_for_eval(file: "backdoor")
  end

  defp log(session_id, value) do
    Backdoor.Session.Log.put_log(via_tuple(Backdoor.Session.Log, session_id), value)
  end
end
