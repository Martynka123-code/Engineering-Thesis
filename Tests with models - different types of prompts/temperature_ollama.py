import ollama
import os
import time
from pathlib import Path
import psutil
import threading

#model_name = 'tinyllama:latest'
#model_name = 'qwen2.5:3b'
model_name = 'llama3.1:8b'
# model_name = 'gemma3:4b'
#model_name = 'phi3.5:latest'

folder_name = "Llama3.1-8b"
context_folder_name = "context-length-4096"

base_output_root = r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\Final tests"


context_size = 4096
# model_top_p = 0.9
# model_seed = 42

llama_process_name_fragment = 'llama-server.exe'

TEMPERATURES = [0.00, 0.15, 0.30, 0.45, 0.60, 0.85, 1.00]


prompts_list = [
#     {
#         "name": "testing-prompt_test-1100010-1100019(10 packets)",
#         "prompt": """You are an IEEE 802.11 security analyst.
#
# Observed facts:
#
# - There are 10 packets in this network sequence in total.
# - Beacon frames from BSSID 0c:9d:92:54:fe:34 (5 frames)
# - 5 deauthentication frames under 1 second
# - Source and destination MAC addresses are often swapped
# - Clients are forced to be off a network repeatedly
#
# Known attacks:
# 1. Deauthentication attack: Massive deauthentication frames causing disconnects
# 2. Evil Twin: Rogue AP impersonates legitimate ESSID
# 3. CSA spoofing: Forged Channel Switch Announcements
#
# Determine:
# - Attack type
# - Confidence
# - Evidence
#
# Please provide a concise and concrete response to this task."""
#     },
#     {
#         "name": "zero-shot_test-1100010-1100019(10 packets)",
#         "prompt": """You are an IEEE 802.11 security analyst.
# Task:
# - Classify the provided network frame sequence into exatcly ONE of the following categories: UNICAST DEAUTHENTICATION ATTACK or NORMAL TRAFFIC.
#
# Rules:
# 1. Use only data provided in the summary below.
# 2. Provide a short, few-sentences explanation of your reasoning.
# 3. Write how many Deauthentication Unicast attacks are present (if there are zero, explicitly write "0").
# 4. State your confidence level in your analysis.
# Network flow summary:
# duration=0.0127
# packet_count=10
# mgmt_packet_count=5
# unprotected_mgmt_count=5
# protected_mgmt_count=0
# unprotected_mgmt_ratio=1.0
# mgmt_subtypes=[12]
# source_addresses={'0c:9d:92:54:fe:34': 3, '88:66:a5:55:a2:d4': 2}
# destination_addresses={'88:66:a5:55:a2:d4': 3, '0c:9d:92:54:fe:34': 2}
# unprotected_source_addresses={'0c:9d:92:54:fe:34': 3, '88:66:a5:55:a2:d4': 2}
# protected_source_addresses={}"""
#     },
#     {
#         "name": "zero-shot_test-1200075-1200084(10 packets)",
#         "prompt": """You are an IEEE 802.11 security analyst.
# Task:
# - Classify the provided network frame sequence into exatcly ONE of the following categories: UNICAST DEAUTHENTICATION ATTACK or NORMAL TRAFFIC.
#
# Rules:
# 1. Use only data provided in the summary below.
# 2. Provide a short, few-sentences explanation of your reasoning.
# 3. Write how many Deauthentication Unicast attacks are present (if there are zero, explicitly write "0").
# 4. State your confidence level in your analysis.
# Network flow summary:
# duration=0.0008
# packet_count=10
# mgmt_packet_count=0
# unprotected_mgmt_count=0
# protected_mgmt_count=0
# unprotected_mgmt_ratio=0.0
# mgmt_subtypes=[]
# source_addresses={'0c:9d:92:54:fe:30': 4}
# destination_addresses={'50:3e:aa:e3:1f:be': 2, '50:3e:aa:e4:01:93': 2}
# unprotected_source_addresses={}
# protected_source_addresses={}"""
#     },
    {
        "name": "testing-prompt_test-1176999-1177098(100 packets)",
        "prompt": """You are an IEEE 802.11 security analyst.

Observed facts:

- There are 100 packets in this network sequence in total.
- Beacon frames from BSSID 0c:9d:92:54:fe:34 (50 frames)
- 46 deauthentication frames under 1 second
- Source and destination MAC addresses are often swapped
- Clients are forced to be off a network repeatedly

Known attacks:
1. Deauthentication attack: Massive deauthentication frames causing disconnects
2. Evil Twin: Rogue AP impersonates legitimate ESSID
3. CSA spoofing: Forged Channel Switch Announcements

Determine:
- Attack type
- Confidence
- Evidence

Please provide a concise and concrete response to this task."""
    },
#     {
#         "name":"testing-prompt_test-1260999-1261999(1000 pakietów)",
#         "prompt": """You are an IEEE 802.11 security analyst.
#
# Observed facts:
#
# - There are 1000 packets in this network sequence in total.
# - Beacon frames from BSSID 0c:9d:92:54:fe:34
# - 144 deauthentication frames in nearly 1 second
# - Source and destination MAC addresses varies
# - Clients are forced to disconnect repeatedly
#
# Known attacks:
# 1. Deauthentication attack: Massive deauthentication frames causing disconnects
# 2. Evil Twin: Rogue AP impersonates legitimate ESSID
# 3. CSA spoofing: Forged Channel Switch Announcements
#
# Determine:
# - Attack type
# - Confidence
# - Evidence
#
# Please provide a concise and concrete response to this task."""
#     }
]

def get_model_identifier(target_model_name: str) -> str:
    try:
        result = ollama.list()
        models_iterable = result.get('models', []) if isinstance(result, dict) else result.models
        for m in models_iterable:
            m_name = m.get('model') if isinstance(m, dict) else getattr(m, 'model', None)
            m_digest = m.get('digest') if isinstance(m, dict) else getattr(m, 'digest', None)
            if m_name == target_model_name:
                return (m_digest or "UNKNOWN")[:12]
    except Exception as e:
        print(f"[WARNING] Failed to retrieve model identifier: {e}")
    return "UNKNOWN"

def get_llama_process_id(process_name_fragment: str) -> list:
    pids = []
    for p in psutil.process_iter(['name', 'pid']):
        name = p.info.get('name')
        if name and process_name_fragment.lower() in name.lower():
            pids.append(p.info['pid'])
    return pids

def is_model_loaded(target_model_name: str) -> bool:
    """Single ollama.ps() check: True if the model is still loaded in memory.
    Returns True on error (safer to assume the model is still running)."""
    try:
        running = ollama.ps()
        running_models = running.get('models', []) if isinstance(running, dict) else running.models
        loaded_names = [(m.get('model') if isinstance(m, dict) else getattr(m, 'model', None))
                        for m in running_models]
        return target_model_name in loaded_names
    except Exception as e:
        print(f"[WARNING] Failed to check ollama.ps(): {e}")
        return True


def unload_model_and_confirm(target_model_name: str, context_size: int = None,
                             delay: float = 0.5, timeout_seconds: float = 30.0,
                             poll_interval: float = 1.0) -> bool:
    """Unload the model and confirm it was unloaded.

    1. wait `delay` s - keep_alive=0 from the previous request has usually already taken effect,
    2. single check: model not loaded -> done (this is the confirmation),
    3. model still loaded -> send one empty request with keep_alive=0,
    4. poll every `poll_interval` s until the model is gone (at most `timeout_seconds`).
    """
    time.sleep(delay)
    if not is_model_loaded(target_model_name):
        print(f"Confirmed: model '{target_model_name}' is already unloaded "
              f"(keep_alive=0 worked) - skipping additional request.")
        return True

    print(f"Model '{target_model_name}' is still visible in ollama.ps() - sending explicit unload request.")
    try:
        options = {'num_ctx': context_size} if context_size is not None else {}
        ollama.generate(
            model = target_model_name,
            prompt = '',
            keep_alive = 0,
            options = options)
    except Exception as e:
        print(f"[WARNING] Failed to send model unload request: {e}")

    waited = 0.0
    while is_model_loaded(target_model_name):
        if waited >= timeout_seconds:
            print(f"[WARNING] Model '{target_model_name}' still visible after {timeout_seconds:.0f}s - "
                  f"continuing anyway, but check it manually.")
            return False
        time.sleep(poll_interval)
        waited += poll_interval
    print(f"Confirmed: model '{target_model_name}' UNLOADED {waited:.1f}s after the request.")
    return True

def log_system_ram(label: str) -> None:
    mem = psutil.virtual_memory()
    used_gb = (mem.total - mem.available) / (1024 ** 3)
    total_gb = mem.total / (1024 ** 3)
    print(f"[System RAM] {label}: used {used_gb:.2f} GB / {total_gb:.2f} GB ({mem.percent}%)")


class LlamaCPUMonitor:
    def __init__(self, process_name_fragment: str, poll_interval: float = 0.2):
        self.process_name_fragment = process_name_fragment.lower()
        self.poll_interval = poll_interval
        self.monitoring = False
        self.measurements = []
        self.thread = None
        self.found_process = False

    def _find_process(self):
        for p in psutil.process_iter(['name']):
            name = p.info.get('name')
            if name and self.process_name_fragment in name.lower():
                try:
                    p.cpu_percent(interval=None)
                    return p
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        return None

    def _monitor(self):
        process = None
        while self.monitoring:
            if process is None:
                process = self._find_process()
                if process is not None:
                    self.found_process = True
                time.sleep(self.poll_interval)
                continue
            try:
                cpu_usage = process.cpu_percent(interval=None) / psutil.cpu_count()
                if cpu_usage > 0:
                    self.measurements.append(cpu_usage)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process = None
            time.sleep(self.poll_interval)

    def start(self):
        self.measurements = []
        self.found_process = False
        self.monitoring = True
        self.thread = threading.Thread(target=self._monitor, daemon=True)
        self.thread.start()

    def stop(self):
        self.monitoring = False
        if self.thread:
            self.thread.join()
        if not self.found_process:
            print(f"[WARNING] No process found with '{self.process_name_fragment}' in its name - check the actual process name in Task Manager.")
        if self.measurements:
            avg_cpu = sum(self.measurements) / len(self.measurements)
            max_cpu = max(self.measurements)
            return avg_cpu, max_cpu
        return 0.0, 0.0


# ================= SINGLE SERIES (one temperature value) ============
def run_temperature_series(model_name, context_size, temperature_value, output_directory_path, model_digest):
    Path(output_directory_path).mkdir(parents=True, exist_ok=True)

    print(f"\n\n##################################################")
    print(f"# NEW SERIES (temperature): model={model_name}, ctx={context_size}, temperature={temperature_value}")
    print(f"# Saving results to: {output_directory_path}")
    print(f"##################################################")
    log_system_ram("RAM at START of this series (before loading the model)")

    for index, prompt_entry in enumerate(prompts_list, start=1):
        test_name = prompt_entry["name"]
        current_prompt = prompt_entry["prompt"]

        print(f"\n==================================================")
        print(f"Starting test {index} of {len(prompts_list)}: {test_name}...")
        #print(f"Parameters: model={model_name}, ctx={context_size}, temperature={temperature_value}, top_p={model_top_p}, seed={model_seed}")
        print(f"Parameters: model={model_name}, ctx={context_size}, temperature={temperature_value}")

        full_prompt = current_prompt
        output_file_name = f'{index:02d}_{test_name}.txt'
        output_file_path = os.path.join(output_directory_path, output_file_name)

        print("---MODEL RESPONSE---")

        model_response = ""
        monitor = LlamaCPUMonitor(llama_process_name_fragment)

        start_time = time.time()
        monitor.start()

        try:
            response = ollama.generate(
                model=model_name,
                prompt=full_prompt,
                keep_alive=0,
                stream=True,
                options={
                    'num_ctx': context_size,
                    'temperature': temperature_value,
                    # 'top_p': model_top_p,
                    # 'seed': model_seed,
                }
            )

            final_chunk = {}
            pids_active = None

            for chunk in response:
                if pids_active is None:
                    pids_active = get_llama_process_id(llama_process_name_fragment)
                    print(f"[Monitor PID] Proces '{llama_process_name_fragment}' currently running: {pids_active}")
                    print("------------------------------------")
                fragment = chunk['response']
                print(fragment, end='', flush=True)
                model_response += fragment
                if chunk.get('done'):
                    final_chunk = chunk

        except Exception as e:
            print(f"\nError during model generation: {e}")
            monitor.stop()
            unload_model_and_confirm(model_name, context_size=context_size)
            continue

        avg_cpu, max_cpu = monitor.stop()
        end_time = time.time()
        execution_time = end_time - start_time

        ollama_total_duration_s = final_chunk.get('total_duration', 0) / 1e9
        ollama_load_duration_s = final_chunk.get('load_duration', 0) / 1e9
        ollama_prompt_eval_count = final_chunk.get('prompt_eval_count', 0)
        ollama_prompt_eval_duration_s = final_chunk.get('prompt_eval_duration', 0) / 1e9
        ollama_eval_count = final_chunk.get('eval_count', 0)
        ollama_eval_duration_s = final_chunk.get('eval_duration', 0) / 1e9
        tokens_per_second = (
            ollama_eval_count / ollama_eval_duration_s if ollama_eval_duration_s > 0 else 0.0
        )

        print(f"\n\n---Statistics for Prompt {index} ({test_name})---")
        print(f"Execution Time (Python, wall-clock): {execution_time:.2f} seconds")
        print(f"Ollama total_duration: {ollama_total_duration_s:.2f} seconds")
        print(f"  - load_duration (loading model): {ollama_load_duration_s:.2f} seconds")
        print(f"  - prompt_eval_duration: {ollama_prompt_eval_duration_s:.2f} seconds ({ollama_prompt_eval_count} tokens)")
        print(f"  - eval_duration (generating response): {ollama_eval_duration_s:.2f} seconds ({ollama_eval_count} tokens, {tokens_per_second:.2f} tok/s)")
        print(f"Average CPU (llama-server): {avg_cpu:.2f}%")
        print(f"Peak CPU (llama-server): {max_cpu:.2f}%")
        print(f"--------------------------------------------------")

        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            output_file.write(f"TEST NAME: {test_name}\n\n")
            output_file.write(f"PROMPT:\n{full_prompt}\n\n")
            output_file.write("---MODEL RESPONSE---\n")
            output_file.write(model_response)
            output_file.write("\n\n---Statistics---\n")
            output_file.write(f"Model: {model_name}\n")
            output_file.write(f"Model digest (ID): {model_digest}\n")
            output_file.write(f"Context size (num_ctx): {context_size}\n")
            output_file.write(f"Temperature: {temperature_value}\n")
            # output_file.write(f"Top_p: {model_top_p}\n")
            # output_file.write(f"Seed: {model_seed}\n")
            output_file.write(f"Execution Time (Python, wall-clock): {execution_time:.2f} seconds\n")
            output_file.write(f"Ollama total_duration: {ollama_total_duration_s:.2f} seconds\n")
            output_file.write(f"Ollama load_duration (loading model): {ollama_load_duration_s:.2f} seconds\n")
            output_file.write(f"Ollama prompt_eval_duration: {ollama_prompt_eval_duration_s:.2f} seconds ({ollama_prompt_eval_count} tokens)\n")
            output_file.write(f"Ollama eval_duration (generating response): {ollama_eval_duration_s:.2f} seconds ({ollama_eval_count} tokens)\n")
            output_file.write(f"Tokens per second: {tokens_per_second:.2f}\n")
            output_file.write(f"Average CPU usage: {avg_cpu:.2f}%\n")
            output_file.write(f"Peak (maximum) CPU usage: {max_cpu:.2f}%\n")

        print(f"Saved to: {output_file_path}")

    print(f"\nUnloading model '{model_name}' after series for temperature={temperature_value}...")
    unload_model_and_confirm(model_name, context_size=context_size)
    log_system_ram("RAM AFTER model unload was confirmed")


# ================= MAIN LOOP: ALL TEMPERATURE VALUES =======
def run_all_tests():
    model_digest = get_model_identifier(model_name)
    print(f"\nModel digest (ID) for '{model_name}': {model_digest}")

    total_series = len(TEMPERATURES)
    series_counter = 0

    for temperature_value in TEMPERATURES:
        series_counter += 1
        temp_folder_name = f"temp_{temperature_value:.2f}"

        output_directory_path = os.path.join(
            base_output_root, folder_name, context_folder_name, "temperatura - bez seed", temp_folder_name
        )

        print(f"\n>>> Series {series_counter}/{total_series} (temperature={temperature_value}) <<<")
        run_temperature_series(model_name, context_size, temperature_value, output_directory_path, model_digest)

    print("\nAll temperature test series completed successfully!")


if __name__ == "__main__":
    run_all_tests()