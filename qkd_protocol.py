"""
Quantum Key Distribution (QKD) Simulation Module
Implements BB84 Protocol for quantum-safe key generation
"""
import random
import hashlib
import uuid
import json
from datetime import datetime, timedelta
from typing import Tuple, List, Dict, Any

class BB84Protocol:
    """
    BB84 Quantum Key Distribution Protocol Simulation
    
    The BB84 protocol uses two bases:
    - Rectilinear basis (+): |0⟩ and |1⟩
    - Diagonal basis (×): |+⟩ and |-⟩
    """
    
    RECTILINEAR = '+'  # 0° and 90°
    DIAGONAL = '×'     # 45° and 135°
    
    def __init__(self, key_length: int = 256):
        self.key_length = key_length
        self.session_id = str(uuid.uuid4())
        self.visualization_data = []
        
    def generate_random_bits(self, length: int) -> List[int]:
        """Generate random classical bits"""
        return [random.randint(0, 1) for _ in range(length)]
    
    def generate_random_bases(self, length: int) -> List[str]:
        """Generate random measurement bases"""
        return [random.choice([self.RECTILINEAR, self.DIAGONAL]) for _ in range(length)]
    
    def encode_qubits(self, bits: List[int], bases: List[str]) -> List[Dict]:
        """
        Encode classical bits into quantum states based on chosen bases
        
        Rectilinear (+):
            - 0 → |0⟩ (horizontal)
            - 1 → |1⟩ (vertical)
        
        Diagonal (×):
            - 0 → |+⟩ (45°)
            - 1 → |-⟩ (135°)
        """
        qubits = []
        for bit, basis in zip(bits, bases):
            if basis == self.RECTILINEAR:
                state = '|0⟩' if bit == 0 else '|1⟩'
                angle = 0 if bit == 0 else 90
            else:
                state = '|+⟩' if bit == 0 else '|-⟩'
                angle = 45 if bit == 0 else 135
            
            qubits.append({
                'bit': bit,
                'basis': basis,
                'state': state,
                'angle': angle,
                'polarization': self._get_polarization_symbol(state)
            })
        return qubits
    
    def _get_polarization_symbol(self, state: str) -> str:
        """Get visual symbol for polarization state"""
        symbols = {
            '|0⟩': '↔',   # Horizontal
            '|1⟩': '↕',   # Vertical
            '|+⟩': '⤢',   # Diagonal (45°)
            '|-⟩': '⤡'    # Anti-diagonal (135°)
        }
        return symbols.get(state, '?')
    
    def measure_qubits(self, qubits: List[Dict], measurement_bases: List[str]) -> List[Dict]:
        """
        Bob measures received qubits with his random bases
        
        If bases match: Measurement gives original bit
        If bases don't match: Random result (50% chance each)
        """
        measurements = []
        for qubit, m_basis in zip(qubits, measurement_bases):
            original_basis = qubit['basis']
            original_bit = qubit['bit']
            
            if m_basis == original_basis:
                # Correct basis: get the original bit
                measured_bit = original_bit
                basis_match = True
            else:
                # Wrong basis: random result
                measured_bit = random.randint(0, 1)
                basis_match = False
            
            measurements.append({
                'original_bit': original_bit,
                'original_basis': original_basis,
                'measurement_basis': m_basis,
                'measured_bit': measured_bit,
                'basis_match': basis_match,
                'state': qubit['state']
            })
        
        return measurements
    
    def sift_key(self, measurements: List[Dict]) -> Tuple[List[int], List[int]]:
        """
        Key sifting: Keep only bits where Alice and Bob used same basis
        Also returns the indices that were kept
        """
        sifted_bits = []
        kept_indices = []
        
        for idx, m in enumerate(measurements):
            if m['basis_match']:
                sifted_bits.append(m['measured_bit'])
                kept_indices.append(idx)
        
        return sifted_bits, kept_indices
    
    def estimate_error_rate(self, alice_bits: List[int], bob_bits: List[int], 
                           sample_size: int = None) -> float:
        """
        Estimate Quantum Bit Error Rate (QBER)
        Uses a sample of bits for error estimation
        """
        if sample_size is None:
            sample_size = min(len(alice_bits) // 4, 50)
        
        if len(alice_bits) < sample_size:
            sample_size = len(alice_bits)
        
        if sample_size == 0:
            return 0.0
        
        # Random sample for error estimation
        indices = random.sample(range(len(alice_bits)), sample_size)
        errors = sum(1 for i in indices if alice_bits[i] != bob_bits[i])
        
        return errors / sample_size
    
    def privacy_amplification(self, key_bits: List[int], target_length: int = None) -> str:
        """
        Privacy amplification using hash function
        Reduces key length to remove any partial information an eavesdropper might have
        """
        if target_length is None:
            target_length = len(key_bits) // 2
        
        # Convert bits to bytes
        bit_string = ''.join(str(b) for b in key_bits)
        key_bytes = int(bit_string, 2).to_bytes((len(bit_string) + 7) // 8, byteorder='big')
        
        # Use SHA-256 for privacy amplification
        hash_obj = hashlib.sha256(key_bytes)
        final_key = hash_obj.hexdigest()[:target_length // 4]  # Each hex char = 4 bits
        
        return final_key
    
    def generate_key(self) -> Dict[str, Any]:
        """
        Complete BB84 QKD Protocol Execution
        Returns all data needed for visualization
        """
        self.visualization_data = []
        
        # Step 1: Alice generates random bits
        alice_bits = self.generate_random_bits(self.key_length * 4)  # Generate more to account for sifting
        self.visualization_data.append({
            'step': 1,
            'name': 'Alice Generates Random Bits',
            'description': 'Alice creates a sequence of random classical bits (0s and 1s)',
            'data': {'bits': alice_bits[:20], 'total': len(alice_bits)}  # Show first 20
        })
        
        # Step 2: Alice chooses random bases
        alice_bases = self.generate_random_bases(len(alice_bits))
        self.visualization_data.append({
            'step': 2,
            'name': 'Alice Chooses Random Bases',
            'description': 'Alice randomly selects Rectilinear (+) or Diagonal (×) basis for each bit',
            'data': {'bases': alice_bases[:20], 'total': len(alice_bases)}
        })
        
        # Step 3: Alice encodes qubits
        qubits = self.encode_qubits(alice_bits, alice_bases)
        self.visualization_data.append({
            'step': 3,
            'name': 'Alice Encodes Qubits',
            'description': 'Alice prepares photons in quantum states based on her bits and bases',
            'data': {'qubits': qubits[:10]}  # Show first 10
        })
        
        # Step 4: Bob chooses random bases
        bob_bases = self.generate_random_bases(len(alice_bits))
        self.visualization_data.append({
            'step': 4,
            'name': 'Bob Chooses Random Bases',
            'description': 'Bob independently selects random measurement bases',
            'data': {'bases': bob_bases[:20]}
        })
        
        # Step 5: Bob measures qubits
        measurements = self.measure_qubits(qubits, bob_bases)
        self.visualization_data.append({
            'step': 5,
            'name': 'Bob Measures Qubits',
            'description': 'Bob measures received photons using his chosen bases',
            'data': {'measurements': measurements[:10]}
        })
        
        # Step 6: Basis reconciliation (public comparison)
        matching_bases = [(i, a, b) for i, (a, b) in enumerate(zip(alice_bases, bob_bases)) if a == b]
        self.visualization_data.append({
            'step': 6,
            'name': 'Basis Reconciliation',
            'description': 'Alice and Bob publicly compare their bases (not the bits!)',
            'data': {
                'matching_count': len(matching_bases),
                'total': len(alice_bases),
                'match_rate': f"{len(matching_bases)/len(alice_bases)*100:.1f}%"
            }
        })
        
        # Step 7: Key sifting
        sifted_bits, kept_indices = self.sift_key(measurements)
        alice_sifted = [alice_bits[i] for i in kept_indices]
        self.visualization_data.append({
            'step': 7,
            'name': 'Key Sifting',
            'description': 'Keep only bits where both used the same basis',
            'data': {
                'sifted_length': len(sifted_bits),
                'alice_sifted': alice_sifted[:20],
                'bob_sifted': sifted_bits[:20]
            }
        })
        
        # Step 8: Error estimation
        error_rate = self.estimate_error_rate(alice_sifted, sifted_bits)
        self.visualization_data.append({
            'step': 8,
            'name': 'Error Rate Estimation',
            'description': 'Check for eavesdropping by comparing a sample of bits',
            'data': {
                'error_rate': f"{error_rate*100:.2f}%",
                'threshold': '11%',
                'secure': error_rate < 0.11
            }
        })
        
        # Check if channel is secure
        if error_rate > 0.11:
            self.visualization_data.append({
                'step': 9,
                'name': 'Security Alert',
                'description': 'Error rate too high - possible eavesdropping detected!',
                'data': {'status': 'ABORT', 'reason': 'Potential eavesdropper detected'}
            })
            return {
                'success': False,
                'error': 'Eavesdropping detected',
                'error_rate': error_rate,
                'visualization': self.visualization_data,
                'session_id': self.session_id
            }
        
        # Step 9: Privacy amplification
        final_key = self.privacy_amplification(sifted_bits, self.key_length)
        key_hash = hashlib.sha256(final_key.encode()).hexdigest()[:16]
        
        self.visualization_data.append({
            'step': 9,
            'name': 'Privacy Amplification',
            'description': 'Hash function applied to remove any leaked information',
            'data': {
                'input_length': len(sifted_bits),
                'output_length': len(final_key) * 4,  # bits
                'key_preview': final_key[:16] + '...'
            }
        })
        
        # Final result
        self.visualization_data.append({
            'step': 10,
            'name': 'Key Generation Complete',
            'description': 'Secure quantum key successfully generated!',
            'data': {
                'key_length_bits': len(final_key) * 4,
                'key_hash': key_hash,
                'error_rate': f"{error_rate*100:.2f}%",
                'secure': True
            }
        })
        
        return {
            'success': True,
            'session_id': self.session_id,
            'alice_bits': ''.join(str(b) for b in alice_bits[:100]),  # Store sample
            'alice_bases': ''.join(alice_bases[:100]),
            'bob_bases': ''.join(bob_bases[:100]),
            'sifted_key': ''.join(str(b) for b in sifted_bits[:100]),
            'final_key': final_key,
            'key_hash': key_hash,
            'error_rate': error_rate,
            'visualization': self.visualization_data,
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(hours=1)).isoformat()
        }

class QKDKeyManager:
    """Manager for QKD keys with refresh and validation"""
    
    def __init__(self, db_connection=None):
        self.db = db_connection
        self.active_keys = {}
    
    def generate_new_key(self, key_length: int = 256) -> Dict[str, Any]:
        """Generate a new QKD key"""
        protocol = BB84Protocol(key_length)
        result = protocol.generate_key()
        
        if result['success']:
            key_id = str(uuid.uuid4())
            result['key_id'] = key_id
            self.active_keys[key_id] = result
        
        return result
    
    def verify_key(self, key_hash: str, provided_key: str) -> bool:
        """Verify if provided key matches the stored key hash"""
        computed_hash = hashlib.sha256(provided_key.encode()).hexdigest()[:16]
        return computed_hash == key_hash
    
    def refresh_key(self, old_key_id: str) -> Dict[str, Any]:
        """Refresh an existing key (generate new key, mark old as inactive)"""
        new_key = self.generate_new_key()
        
        if old_key_id in self.active_keys:
            self.active_keys[old_key_id]['is_active'] = False
            self.active_keys[old_key_id]['replaced_by'] = new_key.get('key_id')
        
        return new_key
    
    def is_key_expired(self, key_data: Dict) -> bool:
        """Check if a key has expired"""
        if 'expires_at' in key_data:
            expiry = datetime.fromisoformat(key_data['expires_at'])
            return datetime.now() > expiry
        return False
    
    def get_key_status(self, key_id: str) -> Dict[str, Any]:
        """Get the status of a key"""
        if key_id not in self.active_keys:
            return {'exists': False}
        
        key_data = self.active_keys[key_id]
        return {
            'exists': True,
            'is_active': key_data.get('is_active', True),
            'is_expired': self.is_key_expired(key_data),
            'error_rate': key_data.get('error_rate', 0),
            'created_at': key_data.get('created_at'),
            'expires_at': key_data.get('expires_at')
        }

def visualize_bb84_step(step_data: Dict) -> str:
    """Generate HTML visualization for a BB84 protocol step"""
    step_num = step_data['step']
    name = step_data['name']
    desc = step_data['description']
    data = step_data['data']
    
    html = f'''
    <div class="qkd-step" id="step-{step_num}">
        <div class="step-header">
            <span class="step-number">{step_num}</span>
            <h4>{name}</h4>
        </div>
        <p class="step-description">{desc}</p>
        <div class="step-data">
    '''
    
    # Add specific visualizations based on step
    if 'bits' in data:
        bits_display = ' '.join(str(b) for b in data['bits'])
        html += f'<div class="bit-sequence">{bits_display}...</div>'
    
    if 'bases' in data:
        bases_display = ' '.join(data['bases'])
        html += f'<div class="bases-sequence">{bases_display}...</div>'
    
    if 'qubits' in data:
        html += '<div class="qubit-display">'
        for q in data['qubits'][:5]:
            html += f'''
            <div class="qubit-state">
                <span class="polarization">{q['polarization']}</span>
                <span class="state-label">{q['state']}</span>
            </div>
            '''
        html += '</div>'
    
    if 'error_rate' in data:
        secure_class = 'secure' if data.get('secure', False) else 'insecure'
        html += f'''
        <div class="error-rate {secure_class}">
            <span>Error Rate: {data['error_rate']}</span>
            <span>Threshold: {data.get('threshold', '11%')}</span>
        </div>
        '''
    
    html += '</div></div>'
    return html


if __name__ == '__main__':
    # Test the BB84 protocol
    print("Testing BB84 QKD Protocol...")
    protocol = BB84Protocol(key_length=256)
    result = protocol.generate_key()
    
    if result['success']:
        print(f"\n✓ Key generated successfully!")
        print(f"  Key ID: {result['session_id']}")
        print(f"  Key Hash: {result['key_hash']}")
        print(f"  Error Rate: {result['error_rate']*100:.2f}%")
        print(f"  Final Key (preview): {result['final_key'][:32]}...")
    else:
        print(f"\n✗ Key generation failed: {result.get('error')}")
    
    print("\nVisualization Steps:")
    for step in result['visualization']:
        print(f"  Step {step['step']}: {step['name']}")
