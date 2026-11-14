import ollama
import os
import time
from pathlib import Path
import psutil
import threading

base_output_root = r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\Final tests"

model_temperature = 0.0
# model_top_p = 0.9
model_seed = 42

llama_process_name_fragment = 'llama-server.exe'

modes_of_tests = ["general", "testing"]

prompts_list = [
    {
        "name": "zero-shot-test",
        "prompt": """You are an IEEE 802.11 security analyst.
Task:
- Classify the provided network frame sequence into exactly ONE of the following categories: UNICAST DEAUTHENTICATION ATTACK or NORMAL TRAFFIC.

Rules:
1. Use only data provided in the file.
2. Provide a short, few-sentences explanation of your reasoning from the beginning till the end.
3. Write how many Deauthentication Unicast attacks are present (if there are zero, explicitly write "0"). Specify the exact packet numbers where they appeared.
4. State your confidence level in your analysis.

Please provide a concise and concrete response to this task.
"""
    },
    {
        "name": "few-shot-test",
         "prompt": """Example 1:
frame.time_relative: 423.847834,
wlan.da: 00:00:00:00:00:08,
wlan.fc.protected: 0,
wlan.fc.type: 0,
wlan.fc.subtype: 12,
wlan.fixed.reason_code: 7.0,
wlan.sa: 00:00:00:00:00:34,
Label: UNICAST DEAUTHENTICATION ATTACK

Task:
- Classify the provided network frame sequence into exactly ONE of the following categories: UNICAST DEAUTHENTICATION ATTACK or NORMAL TRAFFIC.

Rules:
1. Use only the data provided in the input sequence.
2. Provide a short, few-sentences explanation of your reasoning from the beginning till the end.
3. Write how many Deauthentication Unicast attacks are present (if there are zero, explicitly write "0"). Specify the exact packet numbers where they appeared.
4. State your confidence level in your analysis.

Act as an IEEE 802.11 security analyst.
Please provide a concise and concrete response to this task.
"""
    },
#     {
#         "name": "few-shot-test",
#         "prompt":"""Task:
# Analyze the provided sequence of IEEE 802.11 network frames and classify it into EXACTLY ONE of the following categories:
# - UNICAST DEAUTHENTICATION ATTACK
# - NORMAL TRAFFIC
#
# Rules:
# 1. Use only the data provided in the input sequence.
# 2. Provide a short, few-sentences explanation of your reasoning.
# 3. Specify the exact packet numbers where attack frames appear (if none, write "None").
# 4. State your confidence level e.g. (High, Medium, Low).
#
# Example 1:
# frame.time_relative: 423.847834,
# wlan.da: 00:00:00:00:00:08,
# wlan.fc.protected: 0,
# wlan.fc.type: 0,
# wlan.fc.subtype: 12,
# wlan.fixed.reason_code: 7.0,
# wlan.sa: 00:00:00:00:00:34,
# Label: UNICAST DEAUTHENTICATION ATTACK
#
# Classify the provided network frame sequence into exactly ONE of the following categories: UNICAST DEAUTHENTICATION ATTACK or NORMAL TRAFFIC. Provide a short, few-sentences explanation of your reasoning before giving the final label. Act as a cybersecurity analyst specialized in network intrusion detection (IEEE 802.11) and Wi-Fi enterprise networks.
#
# Please provide a concise and concrete response to this task.
# """
#     }
]

testing_prompts = [
    {
        "name": "testing-prompt-test-1",
        "csv_file_name": "packets_1088022-1088027(6 packets).csv",
        "prompt": """You are an IEEE 802.11 security analyst.

Observed facts:

- There are 6 packets in this network sequence in total
- Management frames with BSSID address 0c:9d:92:54:fe:34 (3 frames)
- 1 deauthentication frames under few milliseconds
- Client is transparently forced to be off a network

Known attacks:
1. Deauthentication attack: Massive deauthentication frames causing disconnects
2. Evil Twin: Rogue AP impersonates legitimate ESSID
3. CSA spoofing: Forged Channel Switch Announcements

Determine:
- Attack type
- Confidence
- Evidence

Please provide a concise and concrete response to this task.
"""
    },
    {
        "name": "testing-prompt-test-2",
        "csv_file_name": "packets_1100010-1100019(10 packets).csv",
        "prompt": """You are an IEEE 802.11 security analyst.

Observed facts:

- There are 10 packets in this network sequence in total
- Management frames with BSSID address 0c:9d:92:54:fe:34 (5 frames)
- 5 deauthentication frames under 1 second
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

Please provide a concise and concrete response to this task.
"""
    },
    # {
    #     "name": "testing-prompt-test-3",
    #     "csv_file_name": "packets_1200075-1200084(10 packets).csv",
    #     "prompt": """""",
    # },
    {
        "name": "testing-prompt-test-3",
        "csv_file_name": "packets_1176999-1177098(100 packets).csv",
        "prompt": """You are an IEEE 802.11 security analyst.

Observed facts:

- There are 100 packets in this network sequence in total
- Management and Data frames with BSSID address 0c:9d:92:54:fe:34 (50 frames)
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

Please provide a concise and concrete response to this task.
"""
    },
    {
        "name": "testing-prompt-test-4",
        "csv_file_name": "packets_1260999-1261998(1000 packets).csv",
        "prompt": """You are an IEEE 802.11 security analyst.

Observed facts:

- There are 1000 packets in this network sequence in total
- Management and Data frames with BSSID address 0c:9d:92:54:fe:34 (336 frames)
- 144 deauthentication frames in nearly 1 second
- Source and destination MAC addresses are often swapped
- Clients are forced to disconnect repeatedly

Known attacks:
1. Deauthentication attack: Massive deauthentication frames causing disconnects
2. Evil Twin: Rogue AP impersonates legitimate ESSID
3. CSA spoofing: Forged Channel Switch Announcements

Determine:
- Attack type
- Confidence
- Evidence

Please provide a concise and concrete response to this task.
"""
    },
]

CSV_TEST_FILES = [
    {
        "csv_path": r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\csv\Deauthentication Attack\pliki po 10 pakietów\packets_1088022-1088027(6 packets).csv",
        "subfolder_name": "6 pakietów - packets_1088022-1088027(6 packets)",
    },
    {
        "csv_path": r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\csv\Deauthentication Attack\pliki po 10 pakietów\packets_1100010-1100019(10 packets).csv",
        "subfolder_name": "10 pakietów - 1100010-1100019(10 packets)",
    },
    {
        "csv_path": r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\csv\Deauthentication Attack\pliki po 10 pakietów\packets_1200075-1200084(10 packets).csv",
        "subfolder_name": "10 pakietów - 1200075-1200084(10 packets)",
    },
    {
        "csv_path": r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\csv\Deauthentication Attack\pliki po 100 pakietów\packets_1176999-1177098(100 packets).csv",
        "subfolder_name": "100 pakietów - 1176999-1177098(100 packets)",
    },
    # {
    #     "csv_path": r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\csv\Deauthentication Attack\pliki po 1000 pakietów\packets_1260999-1261998(1000 packets).csv",
    #     "subfolder_name": "1000 pakietów - 1260999-1261999(1000 pakietów)",
    # },
]

MODELS_CONFIGURATION = [
    # {
    #     "model_name": "tinyllama:latest",
    #     "folder_name": "Tinyllama",
    #     "context_configs": [
    #         {"context_size": 2048, "context_folder_name": "context-length-2048"},
    #     ],
    # },
    # {
    #     "model_name": "qwen2.5:3b",
    #     "folder_name": "Qwen",
    #     "context_configs": [
    #         {"context_size": 4096, "context_folder_name": "sprawdzenie - testy"},
    #         {"context_size": 32768, "context_folder_name": "context-length-32768"},
    #     ],
    # },
    # {
    #     "model_name": "gemma3:4b",
    #     "folder_name": "Gemma3-4b",
    #     "context_configs": [
            # {"context_size": 4096, "context_folder_name": "context-length-4096"},
            # {"context_size": 32768, "context_folder_name": "context-length-32768"},
            # {"context_size": 131072, "context_folder_name": "context-length-131072"},
    #     ],
    # },
    # {
    #     "model_name": "phi3.5:latest",
    #     "folder_name": "Phi3.5-latest",
    #     "context_configs": [
    #         # {"context_size": 4096, "context_folder_name": "context-length-4096"},
    #         # {"context_size": 65536, "context_folder_name": "context-length-65536"},
    #         {"context_size": 32768, "context_folder_name": "context-length-32768"},
    #     ],
    # },
    {
        "model_name": "llama3.1:8b",
        "folder_name": "Llama3.1-8b",
        "context_configs": [
    #         # {"context_size": 4096, "context_folder_name": "context-length-4096"},
    #         {"context_size": 32768, "context_folder_name": "context-length-32768"},
                {"context_size": 65536, "context_folder_name": "context-length-65536"},
    #         # {"context_size": 131072, "context_folder_name": "context-length-131072"},
        ],
    },
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

def get_prompts_for_csv(csv_path):
    """Returns the list of prompts to run for a given CSV file,
    combined from all modes in `modes_of_tests` (in that order):

    - "general" -> all prompts from `general_prompts`
      (the same prompts for EVERY CSV file),
    - "testing" -> only those prompts from `testing_prompts`
      whose "csv_file_name" matches the file name from `csv_path`.
    """
    csv_name = os.path.basename(csv_path)
    prompts = []
    for tryb in modes_of_tests:
        if tryb == "general":
            prompts.extend(prompts_list)
        elif tryb == "testing":
            prompts.extend(p for p in testing_prompts
                           if p.get("csv_file_name") == csv_name)
        else:
            print(f"[WARNING] Unknown test mode '{tryb}' - skipping.")
    return prompts

# ================= SINGLE TEST (one model + context + CSV file) =================
def run_single_csv_test(model_name, context_size, output_directory_path, csv_path, model_digest):
    prompts_to_run = get_prompts_for_csv(csv_path)
    if not prompts_to_run:
        print(f"\n[INFO] No prompts (modes {modes_of_tests}) for file "
              f"'{os.path.basename(csv_path)}' - skipping this file.")
        return

    if not os.path.exists(csv_path):
        print(f"Error: The CSV file '{csv_path}' does not exist. Pomijam.")
        return

    Path(output_directory_path).mkdir(parents=True, exist_ok=True)

    with open(csv_path, 'r', encoding='utf-8') as csv_file:
        csv_content = csv_file.read()

    for index, prompt_entry in enumerate(prompts_to_run, start = 1):
        test_name = prompt_entry["name"]
        current_prompt = prompt_entry["prompt"]

        print(f"\n==================================================")
        print(f"Test: {test_name} | model={model_name} | ctx={context_size} | file={os.path.basename(csv_path)}")
        # print(f"Parameters: temp={model_temperature}, top_p={model_top_p}, seed={model_seed}")
        print(f"Parameters: temp={model_temperature}, seed={model_seed}")

        full_prompt = f"{current_prompt}\n\n{csv_content}"
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
                    'temperature': model_temperature,
                    # 'top_p': model_top_p,
                    'seed': model_seed,
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

        print(f"\n\n---Statistics for {test_name}---")
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
            output_file.write(f"Temperature: {model_temperature}\n")
            # output_file.write(f"Top_p: {model_top_p}\n")
            output_file.write(f"Seed: {model_seed}\n")
            output_file.write(f"Execution Time (Python, wall-clock): {execution_time:.2f} seconds\n")
            output_file.write(f"Ollama total_duration: {ollama_total_duration_s:.2f} seconds\n")
            output_file.write(f"Ollama load_duration (loading model): {ollama_load_duration_s:.2f} seconds\n")
            output_file.write(f"Ollama prompt_eval_duration: {ollama_prompt_eval_duration_s:.2f} seconds ({ollama_prompt_eval_count} tokens)\n")
            output_file.write(f"Ollama eval_duration (generating response): {ollama_eval_duration_s:.2f} seconds ({ollama_eval_count} tokens)\n")
            output_file.write(f"Tokens per second: {tokens_per_second:.2f}\n")
            output_file.write(f"Average CPU usage: {avg_cpu:.2f}%\n")
            output_file.write(f"Peak (maximum) CPU usage: {max_cpu:.2f}%\n")

        print(f"Saved to: {output_file_path}")


# ================= SINGLE SERIES (one model + one context, ALL CSV files) =================
def run_context_series(model_name, context_size, context_folder_name, folder_name, model_digest):
    print(f"\n\n##################################################")
    print(f"# NEW SERIES (with file): model={model_name}, num_ctx={context_size}")
    print(f"##################################################")
    log_system_ram("RAM at START of this series (before loading the model)")

    for csv_entry in CSV_TEST_FILES:
        output_directory_path = os.path.join(
            base_output_root, folder_name, context_folder_name, "z plikiem", csv_entry["subfolder_name"]
        )
        run_single_csv_test(model_name, context_size, output_directory_path, csv_entry["csv_path"], model_digest)

    print(f"\nUnloading model '{model_name}' after series for num_ctx={context_size}...")
    unload_model_and_confirm(model_name, context_size=context_size)
    log_system_ram("RAM AFTER model unload was confirmed")


# ================= MAIN LOOP: ALL MODELS x ALL CONTEXTS =================
def run_all_tests():
    total_series = sum(len(cfg["context_configs"]) for cfg in MODELS_CONFIGURATION)
    series_counter = 0

    for model_cfg in MODELS_CONFIGURATION:
        model_name = model_cfg["model_name"]
        folder_name = model_cfg["folder_name"]
        model_digest = get_model_identifier(model_name)
        print(f"\nModel digest (ID) for '{model_name}': {model_digest}")

        for context_cfg in model_cfg["context_configs"]:
            series_counter += 1
            print(f"\n>>> Series {series_counter}/{total_series} <<<")
            run_context_series(
                model_name,
                context_cfg["context_size"],
                context_cfg["context_folder_name"],
                folder_name,
                model_digest,
            )

    print("\nAll test series (with file) completed.")


if __name__ == "__main__":
    run_all_tests()