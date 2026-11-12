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

IN_CONTEXT_PROMPT = """You are an IEEE 802.11 security analyst. 
Analyze provided explanation of an example of network traffic, which demonstrates an example of typical Deauthentication Unicast Attack by sending 2 attacking frames in a network, where Protected Management Frames (PMF) are used. 

Here is a detailed, packet-by-packet description. Pay close attention to the specific column values and their meaning in network sequence.
Packet 1 - It is a fully protected (wlan.fc.protected = 1) example of user data transmission QoS Data (wlan.fc.type = 2, wlan.fc.subtype = 8) from station (STA) 00:00:00:00:00:05 to the Access Point (AP).
Packet 2 - A control frame (wlan.fc.type = 1, wlan.fc.subtype = 9) example which represents the Block ACK from AP station to acknowledge received data from a device 00:00:00:00:00:05.
Packet 3 [ATTACK] - This is a perfect example of a Deauthentication Unicast Attack frame. An attacker tried to disconnect the targeted station (wlan.da = 00:00:00:00:00:08) with an access point by posing as a real AP (wlan.sa = 00:00:00:00:00:34). The key evidence of this attack is that it is a Management frame (wlan.fc.type = 0) and it is a Deauthentication frame (wlan.fc.subtype = 12) and moreover, it is unprotected (wlan.fc.protected = 0) despite network using PMF. Often includes a specific wlan.fixed.reason_code for example 7.0.
Packet 4 - It is an example of standard acknowledgment ACK Control frame after successfully receiving a frame.
Packet 5 [DEFENSE REACTION] - This is a SA Query Request sent by a station 00:00:00:00:00:08 to the real access point 00:00:00:00:00:34, which represents a reaction of endpoint to an unprotected packet. Because the whole network infrastructure work in 802.11w protocol, that is why this device 00:00:00:00:00:08 does not disconnect immediately, but it verifies the packet to the access point. Key values in this packet are Action frame (wlan.fc.type = 0 and wlan.fc.subtype = 13) and it is fully protected (wlan.fc.protected = 1). 
Packet 6 - It is an example of standard acknowledgment ACK Control frame after successfully receiving a frame.
Packet 7 - This is a SA Query Response from the access point to the endpoint, acknowledging that AP is still associated, so the station consider the frame as fake. Key values are (wlan.fc.protected = 1) and the fact that it is an Action frame (wlan.fc.type = 0 and wlan.fc.subtype = 13).
Packet 8 - It is an example of standard acknowledgment ACK Control frame after successfully receiving a frame.
Packet 9 [ANOTHER ATTACK] - There is another example of attempting to disconnect devices in the network. Despite the same attack, attacker tried the opposite method concerned to addresses of devices. In this situation, attacker sends the unprotected attempt addressed to an access point, but posing as a device 00:00:00:00:00:08. Key values are (wlan.fc.protected = 0) and (wlan.fc.type = 0 and wlan.fc.subtype = 12).
Packet 10 - It is an example of standard acknowledgment ACK Control frame after successfully receiving a frame.

In a network using PMF, the definitive signature of a forged Deauthentication frame consists of: wlan.fc.type = 0 and wlan.fc.subtype = 12 and wlan.fc.protected = 0, addressed to a single station. A frame addressed to wlan.da = ff:ff:ff:ff:ff:ff is the broadcast variant and is out of scope here. Note that this sequence above is only an example demonstration of this kind of attack, not a rigid principle. The information provided above is your baseline knowledge.

Now analyze this network CSV file based on the baseline knowledge provided to you previously.
Think step-by-step and follow the tasks below in order.
Your tasks:
- Provide a short, few-sentences explanation of your reasoning.
- Write how many individual frames match the signature (if there are zero, explicitly write "0").
- Write how many distinct attack episodes those frames form. One episode is one distinct pair of (wlan.sa, wlan.da) among the matching frames: a burst of many frames from one spoofed sender to one target is a single episode, while the same attack carried out in the opposite direction is a second episode.
- Specify the exact packet numbers of the matching frames; these numbers refer to the file you are analyzing now, never to the worked example above.
- State your confidence level in your analysis.
- Classify the provided network frame sequence into exactly ONE of the following categories: UNICAST DEAUTHENTICATION ATTACK or NORMAL TRAFFIC.

You MUST format your final response exactly according to the following template:

Reasoning: <your few-sentence explanation>
Attack Frame Count: <number of matching frames>
Attack Episode Count: <number of distinct episodes>
Packet Locations: <list of packet numbers, e.g., 3, 142, 877, or NONE>
Confidence: <Low/Medium/High>
Classification: <UNICAST DEAUTHENTICATION ATTACK or NORMAL TRAFFIC>
"""

CSV_TEST_FILES = [
    # {
    #     "name": "01_6_packets_1088022-1088027(6 packets)",
    #     "csv_path": r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\csv\Deauthentication Attack\pliki po 10 pakietów\packets_1088022-1088027(6 packets).csv",
    # },
    # {
    #     "name": "02_10_packets_1100010-1100019(10 packets)",
    #     "csv_path": r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\csv\Deauthentication Attack\pliki po 10 pakietów\packets_1100010-1100019(10 packets).csv",
    # },
    # {
    #     "name": "03_10_packets_1200075-1200084(10 packets)",
    #     "csv_path": r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\csv\Deauthentication Attack\pliki po 10 pakietów\packets_1200075-1200084(10 packets).csv",
    # },
    # {
    #     "name": "04_100_packets_1176999-1177098(100 packets)",
    #     "csv_path": r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\csv\Deauthentication Attack\pliki po 100 pakietów\packets_1176999-1177098(100 packets).csv",
    # },
    {
        "name": "05_1000_packets_1260999-1261998(1000 packets)",
        "csv_path": r"C:\Users\Martyna\Desktop\moje_rzeczy\STUDIA\inżynierka\datasety\Dane do testów\csv\Deauthentication Attack\pliki po 1000 pakietów\packets_1260999-1261998(1000 packets).csv",
    },
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
            # {"context_size": 4096, "context_folder_name": "context-length-4096"},
    #         {"context_size": 32768, "context_folder_name": "context-length-32768"},
    #     ],
    # },
    # {
    #     "model_name": "gemma3:4b",
    #     "folder_name": "Gemma3-4b",
    #     "context_configs": [
            # {"context_size": 4096, "context_folder_name": "context-length-4096"},
            # {"context_size": 65536, "context_folder_name": "context-length-65536"},
            # {"context_size": 32768, "context_folder_name": "context-length-32768"},
            # {"context_size": 131072, "context_folder_name": "context-length-131072"},
    #     ],
    # },
    {
        "model_name": "phi3.5:latest",
        "folder_name": "Phi3.5-latest",
        "context_configs": [
            # {"context_size": 4096, "context_folder_name": "context-length-4096"},
            # {"context_size": 65536, "context_folder_name": "context-length-65536"},
            {"context_size": 8192, "context_folder_name": "context-length-32768"},
        ],
    },
    {
        "model_name": "llama3.1:8b",
        "folder_name": "Llama3.1-8b",
        "context_configs": [
            # {"context_size": 4096, "context_folder_name": "context-length-4096"},
            # {"context_size": 8192, "context_folder_name": "context-length-32768"},
            {"context_size": 65536, "context_folder_name": "context-length-65536"},
            # {"context_size": 131072, "context_folder_name": "context-length-131072"},
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
        ollama.generate(model=target_model_name, prompt='', keep_alive=0, options=options)
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


# ================= SINGLE TEST (one model + context + CSV file) =================
def run_single_csv_test(model_name, context_size, output_directory_path, csv_path, test_name, model_digest):
    """
    Runs ONE fully self-contained request: IN_CONTEXT_PROMPT
    together with the contents of a single CSV file. No conversation
    history is built or passed here - this is EXACTLY the same mechanism
    as in the "with file" script (ollama.generate, keep_alive=0, no
    memory between calls).
    """
    if not os.path.exists(csv_path):
        print(f"Error: The CSV file '{csv_path}' does not exist. Skipping test '{test_name}'.")
        return

    with open(csv_path, 'r', encoding='utf-8') as csv_file:
        csv_content = csv_file.read()

    full_prompt = f"{IN_CONTEXT_PROMPT}\n\n{csv_content}"
    output_file_path = os.path.join(output_directory_path, f"{test_name}.txt")

    print(f"\n==================================================")
    print(f"Test: {test_name} | model={model_name} | ctx={context_size} | csv_file={os.path.basename(csv_path)}")
    # print(f"Parameters: temp={model_temperature}, top_p={model_top_p}, seed={model_seed}")
    print(f"Parameters: temp={model_temperature}, seed={model_seed}")
    print("---MODEL RESPONSE---")

    model_response = ""
    monitor = LlamaCPUMonitor(llama_process_name_fragment)

    start_time = time.time()
    monitor.start()

    try:
        response = ollama.generate(
            model = model_name,
            prompt = full_prompt,
            # system="You are an IEEE 802.11 security analyst.",
            keep_alive = 0,
            stream = True,
            options = {
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
        return

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


# ================= SINGLE SERIES (one model + one context) ========
def run_context_series(model_name, context_size, output_directory_path, model_digest):
    Path(output_directory_path).mkdir(parents=True, exist_ok=True)

    print(f"\n\n##################################################")
    print(f"# NEW SERIES (In-Context Prompting): model={model_name}, num_ctx={context_size}")
    print(f"# Saving results to: {output_directory_path}")
    print(f"##################################################")

    for csv_entry in CSV_TEST_FILES:
        log_system_ram(f"RAM before test '{csv_entry['name']}' (before loading the model)")

        run_single_csv_test(
            model_name, context_size, output_directory_path,
            csv_entry["csv_path"], csv_entry["name"], model_digest
        )

        print(f"\nUnloading model '{model_name}' after test '{csv_entry['name']}'...")
        unload_model_and_confirm(model_name, context_size=context_size)
        log_system_ram(f"RAM after test '{csv_entry['name']}' finished")


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
            output_directory_path = os.path.join(
                base_output_root, folder_name, context_cfg["context_folder_name"], "In-Context description"
            )

            print(f"\n>>> Series {series_counter}/{total_series} <<<")
            run_context_series(model_name, context_cfg["context_size"], output_directory_path, model_digest)

    print("\nAll tests series (In-Context -> description) completed.")


if __name__ == "__main__":
    run_all_tests()