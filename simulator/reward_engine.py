# reward_engine.py (menggunakan file yang Anda berikan)
def calculate_reward(evaluation_result, verbose=False, weights=None):
    """
    Calculate numeric reward from evaluation status.
    Input: evaluation_result = dict with keys: status, score, summary
    Optional:
        verbose: if True, print rule traces
        weights: dict override for reward base per status
    Output: float reward score [0.0 - 1.0]
    """
    if not isinstance(evaluation_result, dict):
        return 0.0

    default_weights = {
        "SUCCESS": 1.0,
        "BLOCKED": 0.3,
        "ERROR": 0.2,
        "POTENTIAL": 0.6,
        "NO RESPONSE": 0.1,
        "FAILURE": 0.0
    }
    weights = weights or default_weights

    status = evaluation_result.get("status", "FAILURE").upper()
    base_score = evaluation_result.get("score", 0.0)
    summary = evaluation_result.get("summary", "").lower()

    reward = weights.get(status, 0.0)
    if verbose:
        print(f"[Reward] Base reward for status '{status}': {reward}")

    # Bonus if sensitive indicator found
    bonus = 0.0
    if "flag{" in summary:
        bonus += 0.2
        if verbose:
            print("[Reward] Bonus +0.2 for flag{ found")
    if "leak" in summary:
        bonus += 0.2
        if verbose:
            print("[Reward] Bonus +0.2 for leak detected")

    reward += bonus
    final_reward = max(reward, base_score)
    final_reward = round(min(final_reward, 1.0), 4)

    if verbose:
        print(f"[Reward] Final reward (max of reward/base): {final_reward}")

    return final_reward
