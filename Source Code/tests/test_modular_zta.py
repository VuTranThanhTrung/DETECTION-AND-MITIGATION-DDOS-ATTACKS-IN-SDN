import sys
import os
import unittest
from unittest.mock import MagicMock, patch
import pandas as pd
import numpy as np

# Adjust sys.path to import modules from Controller and Emulation
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../Controller')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../Emulation')))

from ml_engine import MLDetectionEngine
from identity_provider import IdentityContextAnalyzer, MockAAAServer
from policy_engine import DynamicPolicyEngine
from mitigation_strategies import MitigationExecutor

class TestMLDetectionEngine(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()

    @patch('os.path.exists')
    @patch('joblib.load')
    def test_load_model_success(self, mock_load, mock_exists):
        mock_exists.return_value = True
        mock_model = MagicMock()
        mock_load.return_value = mock_model

        engine = MLDetectionEngine('dummy_model.pkl', logger=self.logger)
        self.assertTrue(engine.model_loaded)
        self.assertEqual(engine.model, mock_model)

    @patch('os.path.exists')
    def test_load_model_missing_file(self, mock_exists):
        mock_exists.return_value = False
        engine = MLDetectionEngine('dummy_model.pkl', logger=self.logger)
        self.assertFalse(engine.model_loaded)

    @patch('os.path.exists')
    def test_predict_with_empty_dataframe(self, mock_exists):
        mock_exists.return_value = False
        engine = MLDetectionEngine('dummy_model.pkl', logger=self.logger)
        predictions, probabilities = engine.predict(pd.DataFrame())
        self.assertEqual(len(predictions), 0)
        self.assertEqual(len(probabilities), 0)

    @patch('os.path.exists')
    @patch('joblib.load')
    def test_predict_with_valid_flows(self, mock_load, mock_exists):
        mock_exists.return_value = True
        mock_model = MagicMock()
        mock_model.feature_names_in_ = ['feat1', 'feat2']
        mock_model.predict.return_value = np.array([0, 2])
        mock_model.predict_proba.return_value = np.array([[0.9, 0.1], [0.2, 0.8]])
        mock_load.return_value = mock_model

        engine = MLDetectionEngine('dummy_model.pkl', logger=self.logger)
        df = pd.DataFrame({'feat1': [1, 2], 'feat2': [3, 4]})
        predictions, probabilities = engine.predict(df)

        self.assertEqual(list(predictions), [0, 2])
        self.assertEqual(probabilities.shape, (2, 2))


class TestIdentityContextAnalyzer(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.mock_aaa = MagicMock()
        self.mock_aaa.user_db = {
            '10.0.0.7': {'username': 'emp', 'role': 'employee', 'clearance': 'medium'}
        }
        self.mock_aaa.device_db = {
            '10.0.0.7': {'os': 'Windows', 'compliant': True, 'certificates': 'valid'}
        }
        self.analyzer = IdentityContextAnalyzer(self.mock_aaa, logger=self.logger)

    def test_get_user_context_known_ip(self):
        ctx = self.analyzer.get_user_context('10.0.0.7')
        self.assertEqual(ctx['role'], 'employee')

    def test_get_user_context_unknown_ip(self):
        ctx = self.analyzer.get_user_context('10.0.0.99')
        self.assertEqual(ctx['role'], 'unknown')

    def test_get_context_risk_score(self):
        # Known compliant employee: compliant = True (risk base 0.0) + employee role (+0.1) = 0.1
        score = self.analyzer.get_context_risk_score('10.0.0.7')
        self.assertAlmostEqual(score, 0.1)

        # Unknown IP: compliant = False (+0.6) + unknown role (+0.4) = 1.0
        score_unknown = self.analyzer.get_context_risk_score('10.0.0.99')
        self.assertAlmostEqual(score_unknown, 1.0)

    def test_combine_ml_and_context(self):
        # 0.6 * 0.8 + 0.4 * 0.5 = 0.48 + 0.20 = 0.68
        combined = self.analyzer.combine_ml_and_context(0.8, 0.5)
        self.assertAlmostEqual(combined, 0.68)


class TestDynamicPolicyEngine(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.policy = DynamicPolicyEngine(logger=self.logger)

    def test_update_trust_score(self):
        score = self.policy.update_trust_score('10.0.0.7', 0.3)
        self.assertAlmostEqual(score, 0.7)

        score_cap = self.policy.update_trust_score('10.0.0.7', 1.5)
        self.assertAlmostEqual(score_cap, 0.0)

    def test_get_mitigation_action_isolation(self):
        self.policy.update_trust_score('10.0.0.7', 0.7)  # 1.0 - 0.7 = 0.3 (< 0.4)
        action = self.policy.get_mitigation_action('10.0.0.7')
        self.assertEqual(action, "HARD_ISOLATION")

    def test_get_mitigation_action_rate_limit(self):
        self.policy.update_trust_score('10.0.0.7', 0.4)  # 1.0 - 0.4 = 0.6 (0.4 <= score < 0.85)
        action = self.policy.get_mitigation_action('10.0.0.7')
        self.assertEqual(action, "RATE_LIMITING")

    def test_get_mitigation_action_allow(self):
        self.policy.update_trust_score('10.0.0.7', 0.05)  # 1.0 - 0.05 = 0.95 (>= 0.85)
        action = self.policy.get_mitigation_action('10.0.0.7')
        self.assertEqual(action, "ALLOW")

    def test_apply_recovery(self):
        self.policy.update_trust_score('10.0.0.7', 0.5)  # score = 0.5
        self.policy.apply_recovery('10.0.0.7')           # score -> 0.52
        scores = self.policy.get_all_trust_scores()
        self.assertAlmostEqual(scores['10.0.0.7'], 0.52)


class TestMitigationExecutor(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.mock_dp = MagicMock()
        self.mock_dp.id = 1
        self.mock_dp.ofproto = MagicMock()
        self.mock_dp.ofproto_parser = MagicMock()
        self.datapaths = {1: self.mock_dp}
        self.executor = MitigationExecutor(self.datapaths, logger=self.logger)

    def test_configure_meter(self):
        res = self.executor.configure_meter(self.mock_dp, 1, 50)
        self.assertTrue(res)
        self.mock_dp.send_msg.assert_called_once()

    def test_apply_hard_isolation(self):
        res = self.executor.apply_hard_isolation('10.0.0.8')
        self.assertTrue(res)
        # Should send 2 FlowMods (out and in rules)
        self.assertEqual(self.mock_dp.send_msg.call_count, 2)

    def test_apply_rate_limiting(self):
        res = self.executor.apply_rate_limiting('10.0.0.8')
        self.assertTrue(res)
        self.mock_dp.send_msg.assert_called_once()

    def test_remove_restrictions(self):
        self.executor.restricted_ips.add('10.0.0.8')
        res = self.executor.remove_restrictions('10.0.0.8')
        self.assertTrue(res)
        # Should delete inbound and outbound rules (2 operations)
        self.assertEqual(self.mock_dp.send_msg.call_count, 2)


if __name__ == '__main__':
    unittest.main()
