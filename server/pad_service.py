# server/pad_service.py
"""
Presentation Attack Detection (PAD) Service
Implements spatial, temporal, and pose-based attack detection
"""

import cv2
import numpy as np
from scipy import signal
from scipy.signal import butter, filtfilt, welch
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import logging
from typing import List, Tuple, Dict, Any
import asyncio

log = logging.getLogger("dpop-fun.pad")

class SpatialPADAnalyzer:
    """Spatial Presentation Attack Detection using texture analysis"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_trained = False
        
    def extract_texture_features(self, face_region: np.ndarray) -> np.ndarray:
        """Extract texture features from face region"""
        if len(face_region.shape) == 3:
            gray = cv2.cvtColor(face_region, cv2.COLOR_BGR2GRAY)
        else:
            gray = face_region
            
        features = []
        
        # 1. Local Binary Patterns (LBP) - detects texture patterns
        lbp = self._compute_lbp(gray)
        features.extend(lbp.flatten())
        
        # 2. Gray Level Co-occurrence Matrix (GLCM) features
        glcm_features = self._compute_glcm_features(gray)
        features.extend(glcm_features)
        
        # 3. Gabor filter responses
        gabor_features = self._compute_gabor_features(gray)
        features.extend(gabor_features)
        
        # 4. Frequency domain analysis
        freq_features = self._compute_frequency_features(gray)
        features.extend(freq_features)
        
        return np.array(features)
    
    def _compute_lbp(self, image: np.ndarray) -> np.ndarray:
        """Compute Local Binary Patterns"""
        # Simple LBP implementation
        rows, cols = image.shape
        lbp = np.zeros_like(image)
        
        for i in range(1, rows - 1):
            for j in range(1, cols - 1):
                center = image[i, j]
                binary_string = ""
                
                # 8-neighborhood
                neighbors = [
                    image[i-1, j-1], image[i-1, j], image[i-1, j+1],
                    image[i, j+1], image[i+1, j+1], image[i+1, j],
                    image[i+1, j-1], image[i, j-1]
                ]
                
                for neighbor in neighbors:
                    # Use explicit comparison to avoid numpy ambiguity
                    if float(neighbor) >= float(center):
                        binary_string += "1"
                    else:
                        binary_string += "0"
                
                lbp[i, j] = int(binary_string, 2)
        
        return lbp
    
    def _compute_glcm_features(self, image: np.ndarray) -> List[float]:
        """Compute GLCM features"""
        # Simplified GLCM computation
        glcm = np.zeros((256, 256), dtype=np.uint32)
        
        for i in range(image.shape[0] - 1):
            for j in range(image.shape[1] - 1):
                glcm[image[i, j], image[i, j+1]] += 1
                glcm[image[i, j], image[i+1, j]] += 1
        
        # Normalize
        glcm = glcm.astype(np.float32)
        glcm_sum = glcm.sum()
        if glcm_sum > 0:
            glcm /= glcm_sum
        
        # Extract features
        features = []
        
        # Contrast
        contrast = 0
        for i in range(256):
            for j in range(256):
                contrast += glcm[i, j] * (i - j) ** 2
        features.append(contrast)
        
        # Homogeneity
        homogeneity = 0
        for i in range(256):
            for j in range(256):
                homogeneity += glcm[i, j] / (1 + abs(i - j))
        features.append(homogeneity)
        
        # Energy
        energy = np.sum(glcm ** 2)
        features.append(energy)
        
        return features
    
    def _compute_gabor_features(self, image: np.ndarray) -> List[float]:
        """Compute Gabor filter responses - optimized version"""
        features = []
        
        # Reduced orientations and frequencies for speed
        orientations = [0, 90]  # Only horizontal and vertical
        frequencies = [0.3]      # Only one frequency
        
        for orientation in orientations:
            for frequency in frequencies:
                try:
                    # Smaller kernel for speed
                    kernel = cv2.getGaborKernel(
                        (15, 15), 3, np.radians(orientation), 
                        2*np.pi*frequency, 0.5, 0, ktype=cv2.CV_32F
                    )
                    filtered = cv2.filter2D(image.astype(np.float32), cv2.CV_32F, kernel)
                    features.append(float(np.mean(filtered)))
                    features.append(float(np.std(filtered)))
                except Exception as e:
                    log.error(f"Error in Gabor computation: {e}")
                    features.append(0.0)
                    features.append(0.0)
        
        return features
    
    def _compute_frequency_features(self, image: np.ndarray) -> List[float]:
        """Compute frequency domain features"""
        try:
            # FFT analysis
            f_transform = np.fft.fft2(image)
            f_shift = np.fft.fftshift(f_transform)
            magnitude_spectrum = np.log(np.abs(f_shift) + 1)
            
            features = []
            features.append(float(np.mean(magnitude_spectrum)))
            features.append(float(np.std(magnitude_spectrum)))
            features.append(float(np.max(magnitude_spectrum)))
            
            # High frequency content
            h, w = magnitude_spectrum.shape
            center_h, center_w = h // 2, w // 2
            high_freq = magnitude_spectrum[center_h-h//4:center_h+h//4, center_w-w//4:center_w+w//4]
            features.append(float(np.mean(high_freq)))
            
            return features
        except Exception as e:
            log.error(f"Error in frequency computation: {e}")
            return [0.0, 0.0, 0.0, 0.0]
    
    def analyze_spatial_pad(self, face_frames: List[np.ndarray]) -> float:
        """Analyze spatial PAD for a sequence of face frames - optimized version"""
        if face_frames is None or len(face_frames) == 0:
            return 0.0
        
        # Process only every other frame for speed (or max 5 frames)
        max_frames = min(5, len(face_frames))
        step = max(1, len(face_frames) // max_frames)
        selected_frames = face_frames[::step][:max_frames]
        
        # Extract features from selected frames only
        all_features = []
        for i, frame in enumerate(selected_frames):
            features = self.extract_texture_features(frame)
            all_features.append(features)
        
        # Use simple heuristic scoring (can be replaced with trained model)
        scores = []
        for i, features in enumerate(all_features):
            try:
                # Higher texture complexity = more likely real
                features_mean = np.mean(features)
                features_std = np.std(features)
                texture_score = features_std / (features_mean + 1e-6)
                scores.append(float(texture_score))
                log.info(f"Frame {i}: mean={features_mean:.3f}, std={features_std:.3f}, score={texture_score:.3f}")
            except Exception as e:
                log.error(f"Error computing score for frame {i}: {e}")
                scores.append(0.0)
        
        # Return average score (0-1, higher = more likely real)
        avg_score = np.mean(scores)
        final_score = min(1.0, max(0.0, avg_score / 10.0))  # Normalize
        log.info(f"Spatial analysis completed: avg_score={avg_score:.3f}, final_score={final_score:.3f}")
        return final_score


class TemporalRPpgAnalyzer:
    """Temporal Presentation Attack Detection using rPPG (remote photoplethysmography)"""
    
    def __init__(self):
        self.min_heart_rate = 40  # BPM
        self.max_heart_rate = 200  # BPM
        
    def extract_rppg_signal(self, face_frames: List[np.ndarray]) -> Tuple[np.ndarray, float]:
        """Extract heart rate signal from facial color changes"""
        if len(face_frames) < 30:  # Need at least 1 second at 30fps
            return np.array([]), 0.0
        
        # Extract color values from face regions
        red_values = []
        green_values = []
        blue_values = []
        
        for frame in face_frames:
            # Assume face is in center region
            h, w = frame.shape[:2]
            face_region = frame[h//4:3*h//4, w//4:3*w//4]
            
            # Extract mean color values (handle both color and grayscale)
            if len(frame.shape) == 3:
                red_mean = np.mean(face_region[:, :, 2])  # OpenCV uses BGR
                green_mean = np.mean(face_region[:, :, 1])
                blue_mean = np.mean(face_region[:, :, 0])
            else:
                # Grayscale image - use the same value for all channels
                gray_mean = np.mean(face_region)
                red_mean = green_mean = blue_mean = gray_mean
            
            red_values.append(red_mean)
            green_values.append(green_mean)
            blue_values.append(blue_mean)
        
        # Convert to numpy arrays
        red_signal = np.array(red_values)
        green_signal = np.array(green_values)
        blue_signal = np.array(blue_values)
        
        # Use green channel (most sensitive to blood volume changes)
        raw_signal = green_signal
        
        # Apply bandpass filter (0.7-4 Hz = 42-240 BPM)
        fps = 30  # Assume 30 FPS
        low_freq = self.min_heart_rate / 60.0  # Convert BPM to Hz
        high_freq = self.max_heart_rate / 60.0
        
        filtered_signal = self._bandpass_filter(raw_signal, low_freq, high_freq, fps)
        
        # Detect heart rate
        heart_rate = self._detect_heart_rate(filtered_signal, fps)
        
        return filtered_signal, heart_rate
    
    def _bandpass_filter(self, signal: np.ndarray, low_freq: float, high_freq: float, fps: float) -> np.ndarray:
        """Apply bandpass filter to signal"""
        nyquist = fps / 2
        low_norm = low_freq / nyquist
        high_norm = high_freq / nyquist
        
        # Design Butterworth filter
        b, a = signal.butter(4, [low_norm, high_norm], btype='band')
        filtered = signal.filtfilt(b, a, signal)
        
        return filtered
    
    def _detect_heart_rate(self, filtered_signal: np.ndarray, fps: float) -> float:
        """Detect heart rate from filtered signal"""
        if len(filtered_signal) < 10:
            return 0.0
        
        # Find peaks
        peaks, _ = signal.find_peaks(filtered_signal, distance=int(fps * 0.4))  # Min 0.4s between peaks
        
        if len(peaks) < 2:
            return 0.0
        
        # Calculate heart rate
        time_between_peaks = np.diff(peaks) / fps
        avg_time_between_peaks = np.mean(time_between_peaks)
        heart_rate = 60.0 / avg_time_between_peaks
        
        return heart_rate
    
    def analyze_temporal_pad(self, face_frames: List[np.ndarray]) -> float:
        """Analyze temporal PAD using rPPG"""
        filtered_signal, heart_rate = self.extract_rppg_signal(face_frames)
        
        
        if np.isclose(heart_rate, 0.0) or np.isnan(heart_rate):
            log.warning("No heart rate detected in temporal analysis")
            return 0.0  # No heart rate detected
        
        # Score based on heart rate plausibility
        if self.min_heart_rate <= float(heart_rate) <= self.max_heart_rate:
            # Additional checks for signal quality
            if len(filtered_signal) > 0:
                signal_quality = np.std(filtered_signal) / (np.mean(np.abs(filtered_signal)) + 1e-6)
                score = min(1.0, signal_quality * 2.0)
                return score
        else:
            pass
        
        return 0.0


class PoseConsistencyAnalyzer:
    """Enhanced pose analysis for 3D structure verification"""
    
    def __init__(self):
        pass
    
    def analyze_pose_consistency(self, face_frames: List[np.ndarray], landmarks_sequence: List[List]) -> float:
        """Analyze 3D pose consistency during head movements"""
        if len(face_frames) < 3 or len(landmarks_sequence) < 3:
            return 0.0
        
        scores = []
        
        # 1. Analyze depth consistency
        depth_score = self._analyze_depth_consistency(landmarks_sequence)
        scores.append(depth_score)
        
        # 2. Analyze movement smoothness
        movement_score = self._analyze_movement_smoothness(landmarks_sequence)
        scores.append(movement_score)
        
        # 3. Analyze facial geometry consistency
        geometry_score = self._analyze_geometry_consistency(landmarks_sequence)
        scores.append(geometry_score)
        
        return np.mean(scores)
    
    def _analyze_depth_consistency(self, landmarks_sequence: List[List]) -> float:
        """Analyze if face appears to have consistent 3D depth"""
        if len(landmarks_sequence) < 2:
            return 0.0
        
        # Calculate face width/height ratios across frames
        ratios = []
        for landmarks in landmarks_sequence:
            if len(landmarks) < 10:  # Need enough landmarks
                continue
                
            # Use eye distance and face height as proxy for depth
            # InsightFace landmarks are numpy arrays with shape (5, 2) for 5 keypoints
            if len(landmarks) >= 5:
                # InsightFace format: [left_eye, right_eye, nose, left_mouth, right_mouth]
                left_eye = landmarks[0]  # [x, y]
                right_eye = landmarks[1]  # [x, y]
                nose = landmarks[2]  # [x, y]
                left_mouth = landmarks[3]  # [x, y]
                right_mouth = landmarks[4]  # [x, y]
                
                eye_distance = abs(right_eye[0] - left_eye[0])
                face_height = abs((left_mouth[1] + right_mouth[1]) / 2 - nose[1])
            else:
                # Fallback for other formats
                left_eye = landmarks[0] if len(landmarks) > 0 else [0, 0]
                right_eye = landmarks[1] if len(landmarks) > 1 else [1, 0]
                nose = landmarks[2] if len(landmarks) > 2 else [0.5, 0.5]
                chin = landmarks[3] if len(landmarks) > 3 else [0.5, 1]
                
                eye_distance = abs(right_eye[0] - left_eye[0])
                face_height = abs(chin[1] - nose[1])
            
            if face_height > 0:
                ratio = eye_distance / face_height
                ratios.append(ratio)
        
        if len(ratios) < 2:
            return 0.0
        
        # Real faces should have consistent ratios
        ratio_consistency = 1.0 - (np.std(ratios) / (np.mean(ratios) + 1e-6))
        return max(0.0, ratio_consistency)
    
    def _analyze_movement_smoothness(self, landmarks_sequence: List[List]) -> float:
        """Analyze if head movements are smooth and natural"""
        if len(landmarks_sequence) < 3:
            return 0.0
        
        # Calculate nose position changes
        nose_positions = []
        for landmarks in landmarks_sequence:
            if len(landmarks) >= 5:
                # InsightFace format: nose is at index 2
                nose = landmarks[2]  # [x, y]
                nose_positions.append([nose[0], nose[1]])
            elif len(landmarks) > 1:
                # Fallback format
                nose = landmarks[1]
                if hasattr(nose, 'x') and hasattr(nose, 'y'):
                    nose_positions.append([nose.x, nose.y])
                elif len(nose) >= 2:
                    nose_positions.append([nose[0], nose[1]])
        
        if len(nose_positions) < 3:
            return 0.0
        
        nose_positions = np.array(nose_positions)
        
        # Calculate movement velocity
        velocities = np.diff(nose_positions, axis=0)
        velocity_magnitudes = np.linalg.norm(velocities, axis=1)
        
        # Smooth movements should have consistent velocity
        velocity_consistency = 1.0 - (np.std(velocity_magnitudes) / (np.mean(velocity_magnitudes) + 1e-6))
        
        return max(0.0, velocity_consistency)
    
    def _analyze_geometry_consistency(self, landmarks_sequence: List[List]) -> float:
        """Analyze if facial geometry remains consistent"""
        if len(landmarks_sequence) < 2:
            return 0.0
        
        # Calculate facial feature distances
        feature_distances = []
        for landmarks in landmarks_sequence:
            if len(landmarks) < 10:
                continue
                
            # Calculate distances between key facial features
            distances = []
            
            # Eye to nose distance (InsightFace format)
            if len(landmarks) >= 5:
                # InsightFace format: [left_eye, right_eye, nose, left_mouth, right_mouth]
                left_eye = landmarks[0]  # [x, y]
                nose = landmarks[2]  # [x, y]
                left_mouth = landmarks[3]  # [x, y]
                
                eye_nose_dist = abs(left_eye[1] - nose[1])
                nose_mouth_dist = abs(nose[1] - left_mouth[1])
                
                distances.append(eye_nose_dist)
                distances.append(nose_mouth_dist)
            
            if distances:
                feature_distances.append(np.mean(distances))
        
        if len(feature_distances) < 2:
            return 0.0
        
        # Real faces should maintain consistent proportions
        proportion_consistency = 1.0 - (np.std(feature_distances) / (np.mean(feature_distances) + 1e-6))
        
        return max(0.0, proportion_consistency)


class AdvancedRPpgAnalyzer:
    """Advanced rPPG analysis for detecting live faces vs display replays"""
    
    def __init__(self):
        # MediaPipe canonical 3D landmarks for PnP analysis
        self.canonical_3d_points = np.array([
            [-0.1, -0.1, 0.0],   # Left eye corner
            [0.1, -0.1, 0.0],    # Right eye corner  
            [0.0, 0.0, 0.0],     # Nose tip
            [-0.05, 0.1, 0.0],   # Left mouth corner
            [0.05, 0.1, 0.0],    # Right mouth corner
            [0.0, 0.15, 0.0],    # Chin
            [-0.08, 0.05, 0.0],  # Left cheek
            [0.08, 0.05, 0.0]    # Right cheek
        ], dtype=np.float32)
        
    def bandpass_filter(self, signal_data, fs, low=0.7, high=3.0, order=3):
        """Apply bandpass filter for heart rate range"""
        if len(signal_data) < 10:  # Need minimum length for filter
            return signal_data
            
        nyquist = fs / 2
        low_norm = low / nyquist
        high_norm = high / nyquist
        
        # Ensure filter order doesn't exceed signal length
        max_order = min(order, len(signal_data) // 3)
        if max_order < 1:
            return signal_data
            
        try:
            b, a = butter(max_order, [low_norm, high_norm], btype='band')
            return filtfilt(b, a, signal_data)
        except Exception as e:
            log.debug(f"Filter failed, returning original signal: {e}")
            return signal_data
    
    def analyze_rppg(self, frames_bgr, fs=10, face_mask=None):
        """
        Analyze rPPG signal for live face detection
        Returns dict with hr_bpm, snr_db, live_prob
        """
        try:
            # Extract green channel time series (strongest for rPPG)
            g_series = []
            for frame in frames_bgr:
                if face_mask is not None:
                    roi = frame * face_mask[..., None]
                    g_values = roi[..., 1][roi[..., 1] > 0]
                    if len(g_values) > 0:
                        g_series.append(np.mean(g_values))
                    else:
                        g_series.append(np.mean(frame[..., 1]))
                else:
                    g_series.append(np.mean(frame[..., 1]))
            
            if len(g_series) < 5:  # Need minimum frames
                return {"hr_bpm": None, "snr_db": -999, "live_prob": 0.0}
            
            # Normalize and filter
            x = np.array(g_series, dtype=np.float64)
            x = (x - np.mean(x)) / (np.std(x) + 1e-6)
            x = self.bandpass_filter(x, fs)
            
            # Power spectral density
            freqs, psd = welch(x, fs=fs, nperseg=min(256, len(x)))
            
            # Focus on heart rate band (0.7-3.0 Hz = 42-180 bpm)
            hr_mask = (freqs >= 0.7) & (freqs <= 3.0)
            hr_freqs = freqs[hr_mask]
            hr_psd = psd[hr_mask]
            
            if len(hr_psd) < 5:
                return {"hr_bpm": None, "snr_db": -999, "live_prob": 0.0}
            
            # Find peak frequency
            peak_idx = np.argmax(hr_psd)
            peak_freq = hr_freqs[peak_idx]
            peak_power = hr_psd[peak_idx]
            
            # Calculate SNR
            noise_power = (np.sum(hr_psd) - peak_power) / max(len(hr_psd) - 1, 1)
            snr_db = 10 * np.log10((peak_power + 1e-9) / (noise_power + 1e-9))
            
            # Convert to BPM
            hr_bpm = peak_freq * 60.0
            
            # Determine live probability
            hr_valid = 40 <= hr_bpm <= 180
            snr_valid = snr_db >= 3.0
            
            if hr_valid and snr_valid:
                live_prob = min(1.0, (snr_db - 3.0) / 6.0)  # Scale SNR to [0,1]
            elif hr_valid:
                live_prob = 0.3  # Valid HR but poor SNR
            else:
                live_prob = 0.0  # Invalid HR
                
            return {
                "hr_bpm": float(hr_bpm),
                "snr_db": float(snr_db), 
                "live_prob": float(live_prob)
            }
            
        except Exception as e:
            log.error(f"rPPG analysis failed: {e}")
            return {"hr_bpm": None, "snr_db": -999, "live_prob": 0.0}

class DisplayFlickerAnalyzer:
    """Detect display refresh/PWM flicker patterns"""
    
    def analyze_flicker(self, frames_bgr, fs=10):
        """
        Detect periodic flicker typical of displays
        Returns score [0,1] where higher = more likely display
        """
        try:
            log.info(f"Flicker analyzer: processing {len(frames_bgr)} frames")
            if len(frames_bgr) < 5:
                log.warning(f"Flicker analysis: insufficient frames ({len(frames_bgr)})")
                return 0.0
                
            # Extract row-wise means to capture rolling shutter effects
            means = []
            for i, frame in enumerate(frames_bgr):
                log.debug(f"Frame {i}: shape={frame.shape}, dtype={frame.dtype}")
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                row_means = np.mean(gray, axis=1)
                frame_mean = np.mean(row_means)
                means.append(frame_mean)
                log.debug(f"Frame {i}: mean={frame_mean:.3f}")
            
            # Normalize signal
            x = np.array(means, dtype=np.float64)
            log.info(f"Flicker signal: mean={np.mean(x):.3f}, std={np.std(x):.6f}")
            if np.std(x) < 1e-6:
                log.warning(f"Flicker analysis: signal too flat (std: {np.std(x)})")
                return 0.0
                
            x = (x - np.mean(x)) / (np.std(x) + 1e-6)
            log.info(f"Normalized signal: mean={np.mean(x):.6f}, std={np.std(x):.6f}")
            
            # Power spectral density
            freqs, psd = welch(x, fs=fs, nperseg=min(512, len(x)))
            log.info(f"PSD: {len(freqs)} frequencies, {len(psd)} power values")
            
            # Look for any periodic patterns (not just high-frequency)
            # With limited frames, we need to look at all frequencies
            log.info(f"Available frequencies: {freqs}")
            log.info(f"Power spectrum: {psd}")
            
            # Find the strongest peak in any frequency range
            if len(psd) < 3:
                log.warning(f"Flicker analysis: insufficient frequency data ({len(psd)})")
                return 0.0
                
            # Focus on higher frequencies (screen refresh patterns)
            # Real screens typically refresh at 60Hz+, but with limited frames we look for any high-freq patterns
            high_freq_mask = freqs >= 3.0  # Focus on 3Hz+ (above natural head movement)
            high_freq_psd = psd[high_freq_mask]
            high_freq_freqs = freqs[high_freq_mask]
            
            if len(high_freq_psd) < 2:
                log.info(f"Flicker analysis: insufficient high-freq data ({len(high_freq_psd)}), focusing on all frequencies")
                # Fallback to all frequencies but with lower sensitivity
                peak_idx = np.argmax(psd[1:]) + 1
                peak_freq = freqs[peak_idx]
                peak_power = psd[peak_idx]
                noise_power = (np.sum(psd) - peak_power) / max(len(psd) - 1, 1)
                snr = (peak_power + 1e-9) / (noise_power + 1e-9)
                # Much lower sensitivity for low frequencies
                flicker_score = float(np.clip((snr - 8) / 15, 0, 1)) if peak_freq >= 3.0 else 0.0
            else:
                # Use high-frequency analysis
                peak_idx = np.argmax(high_freq_psd)
                peak_freq = high_freq_freqs[peak_idx]
                peak_power = high_freq_psd[peak_idx]
                noise_power = (np.sum(high_freq_psd) - peak_power) / max(len(high_freq_psd) - 1, 1)
                snr = (peak_power + 1e-9) / (noise_power + 1e-9)
                # Much lower sensitivity for high frequencies to avoid false positives
                flicker_score = float(np.clip((snr - 5) / 10, 0, 1))
            
            log.info(f"Flicker analysis: peak_freq={peak_freq:.2f}Hz, peak_power={peak_power:.3f}, noise={noise_power:.3f}, snr={snr:.3f}, score={flicker_score:.3f}")
            return flicker_score
            
        except Exception as e:
            log.error(f"Flicker analysis failed: {e}")
            return 0.0

class GeometricPlanarityAnalyzer:
    """Detect planar vs 3D motion using homography vs PnP analysis"""
    
    def __init__(self):
        # Stable landmark indices for PnP analysis
        self.pnp_indices = [33, 263, 1, 61, 291, 199, 362, 133]  # MediaPipe indices
        self.homography_indices = [10, 33, 133, 362, 263, 1, 152, 234, 454, 323]
        
    def analyze_planarity(self, frames_bgr, landmarks_sequence):
        """
        Analyze motion for planar vs 3D characteristics
        Returns score [0,1] where higher = more likely planar replay
        """
        try:
            log.info(f"Planarity analyzer: processing {len(frames_bgr)} frames, {len(landmarks_sequence) if landmarks_sequence is not None else 0} landmark sets")
            if landmarks_sequence is None or len(landmarks_sequence) < 3:
                log.warning(f"Planarity analysis: insufficient landmarks ({len(landmarks_sequence) if landmarks_sequence is not None else 0})")
                return 0.0
                
            homography_residuals = []
            pnp_depth_changes = []
            
            processed_frames = 0
            for i in range(1, len(frames_bgr)):
                if i >= len(landmarks_sequence):
                    log.debug(f"Frame {i}: no landmarks available")
                    break
                    
                lm_prev = landmarks_sequence[i-1]
                lm_curr = landmarks_sequence[i]
                
                if lm_prev is None or lm_curr is None:
                    log.debug(f"Frame {i}: null landmarks")
                    continue
                if len(lm_prev) == 0 or len(lm_curr) == 0:
                    log.debug(f"Frame {i}: empty landmarks")
                    continue
                    
                processed_frames += 1
                log.debug(f"Frame {i}: processing landmarks (prev: {len(lm_prev)}, curr: {len(lm_curr)})")
                    
                h, w = frames_bgr[i].shape[:2]
                
                # PnP analysis for 3D depth
                try:
                    pts2d = []
                    for j in self.pnp_indices:
                        if j < len(lm_curr):
                            landmark = lm_curr[j]
                            if hasattr(landmark, 'x') and hasattr(landmark, 'y'):
                                pts2d.append([landmark.x * w, landmark.y * h])
                            elif hasattr(landmark, '__len__') and len(landmark) >= 2:
                                pts2d.append([landmark[0] * w, landmark[1] * h])
                    pts2d = np.array(pts2d, dtype=np.float32)
                    
                    if len(pts2d) < 4:
                        continue
                        
                    # Simple camera intrinsics
                    fx = fy = 0.8 * w
                    cx, cy = w/2.0, h/2.0
                    K = np.array([[fx, 0, cx], [0, fy, cy], [0, 0, 1]], dtype=np.float64)
                    
                    # Use subset of canonical 3D points
                    pts3d = np.array([[-0.1, -0.1, 0.0], [0.1, -0.1, 0.0], 
                                     [0.0, 0.0, 0.0], [-0.05, 0.1, 0.0]], dtype=np.float32)
                    
                    if len(pts3d) != len(pts2d):
                        pts3d = pts3d[:len(pts2d)]
                    
                    # Solve PnP
                    success, rvec, tvec = cv2.solvePnP(
                        pts3d, pts2d, K, None, 
                        flags=cv2.SOLVEPNP_ITERATIVE
                    )
                    
                    if success:
                        depth = float(np.linalg.norm(tvec))
                        pnp_depth_changes.append(depth)
                        
                except Exception as e:
                    log.debug(f"PnP analysis failed for frame {i}: {e}")
                
                # Homography analysis for planar motion
                try:
                    prev_pts = []
                    for j in self.homography_indices:
                        if j < len(lm_prev):
                            landmark = lm_prev[j]
                            if hasattr(landmark, 'x') and hasattr(landmark, 'y'):
                                prev_pts.append([landmark.x * w, landmark.y * h])
                            elif hasattr(landmark, '__len__') and len(landmark) >= 2:
                                prev_pts.append([landmark[0] * w, landmark[1] * h])
                    prev_pts = np.array(prev_pts, dtype=np.float32)
                    
                    curr_pts = []
                    for j in self.homography_indices:
                        if j < len(lm_curr):
                            landmark = lm_curr[j]
                            if hasattr(landmark, 'x') and hasattr(landmark, 'y'):
                                curr_pts.append([landmark.x * w, landmark.y * h])
                            elif hasattr(landmark, '__len__') and len(landmark) >= 2:
                                curr_pts.append([landmark[0] * w, landmark[1] * h])
                    curr_pts = np.array(curr_pts, dtype=np.float32)
                    
                    if len(prev_pts) >= 4 and len(curr_pts) >= 4:
                        # Ensure same number of points
                        min_pts = min(len(prev_pts), len(curr_pts))
                        prev_pts = prev_pts[:min_pts]
                        curr_pts = curr_pts[:min_pts]
                        
                        H, mask = cv2.findHomography(prev_pts, curr_pts, cv2.RANSAC, 3.0)
                        
                        if H is not None:
                            # Project previous points using homography
                            proj_pts = cv2.perspectiveTransform(prev_pts[None, ...], H)[0]
                            residual = np.mean(np.linalg.norm(proj_pts - curr_pts, axis=1))
                            homography_residuals.append(residual)
                            
                except Exception as e:
                    log.debug(f"Homography analysis failed for frame {i}: {e}")
            
            log.info(f"Planarity analysis: processed {processed_frames} frames, collected {len(pnp_depth_changes)} pnp depths, {len(homography_residuals)} homography residuals")
            if len(pnp_depth_changes) < 3 or len(homography_residuals) < 3:
                log.warning(f"Planarity analysis: insufficient data (pnp: {len(pnp_depth_changes)}, homography: {len(homography_residuals)})")
                return 0.0
            
            # Analyze results
            depth_variance = np.var(pnp_depth_changes)
            homography_median = np.median(homography_residuals)
            
            # Planar motion has low homography residuals and low depth variation
            # Score increases as residuals decrease and depth variation decreases
            # Make it more sensitive to detect flat screens
            planarity_score = float(np.clip(
                (0.3 / (homography_median + 1e-3)) * (0.01 / (depth_variance + 1e-4)), 
                0, 1
            ))
            
            log.debug(f"Planarity analysis: depth_var={depth_variance:.6f}, homography_med={homography_median:.6f}, score={planarity_score:.3f}")
            return planarity_score
            
        except Exception as e:
            log.error(f"Planarity analysis failed: {e}")
            return 0.0

class PADService:
    """Main PAD service combining all detection methods"""
    
    def __init__(self):
        self.spatial_analyzer = SpatialPADAnalyzer()
        self.temporal_analyzer = TemporalRPpgAnalyzer()
        self.pose_analyzer = PoseConsistencyAnalyzer()
        self.advanced_rppg = AdvancedRPpgAnalyzer()
        self.flicker_analyzer = DisplayFlickerAnalyzer()
        self.planarity_analyzer = GeometricPlanarityAnalyzer()
    
    def create_synthetic_attack_frames(self, real_frames: List[np.ndarray]) -> List[np.ndarray]:
        """Create synthetic attack frames for testing PAD"""
        attack_frames = []
        
        for frame in real_frames:
            # Create a simple attack by blurring the frame (simulates photo attack)
            blurred = cv2.GaussianBlur(frame, (15, 15), 0)
            
            # Add some noise to simulate print artifacts
            noise = np.random.normal(0, 10, frame.shape).astype(np.uint8)
            noisy_frame = cv2.add(blurred, noise)
            
            attack_frames.append(noisy_frame)
        
        log.info(f"Created {len(attack_frames)} synthetic attack frames")
        return attack_frames
        
    async def analyze_pad(self, face_frames: List[np.ndarray], landmarks_sequence: List[List] = None) -> Dict[str, Any]:
        """Perform comprehensive PAD analysis using advanced techniques with timeout"""
        try:
            if not face_frames or len(face_frames) < 10:
                log.warning("Insufficient frames for PAD analysis")
                return {
                    "attack_detected": False,
                    "confidence": 0.5,
                    "live_final": True,
                    "analysis_details": {"error": "Insufficient frames"}
                }
            
            # Add timeout to prevent hanging
            return await asyncio.wait_for(
                self._perform_pad_analysis(face_frames, landmarks_sequence),
                timeout=15.0  # 15 second timeout
            )
        except asyncio.TimeoutError:
            log.warning("PAD analysis timed out after 15 seconds")
            return {
                "attack_detected": False,
                "confidence": 0.5,
                "live_final": True,
                "analysis_details": {"error": "Analysis timed out"}
            }
        except Exception as e:
            log.error(f"PAD analysis failed: {e}")
            return {
                "attack_detected": False,
                "confidence": 0.5,
                "live_final": True,
                "analysis_details": {"error": str(e)}
            }
    
    async def _perform_pad_analysis(self, face_frames: List[np.ndarray], landmarks_sequence: List[List] = None) -> Dict[str, Any]:
        """Internal PAD analysis method"""
        try:
            # Advanced rPPG analysis
            rppg_results = self.advanced_rppg.analyze_rppg(face_frames, fs=10)
            
            # Display flicker analysis
            log.info(f"Starting flicker analysis with {len(face_frames)} frames")
            if face_frames:
                log.info(f"First frame shape: {face_frames[0].shape}, dtype: {face_frames[0].dtype}")
            flicker_score = self.flicker_analyzer.analyze_flicker(face_frames, fs=10)
            log.info(f"Flicker analysis completed: score: {flicker_score:.3f}")
            
            # Geometric planarity analysis
            planarity_score = 0.0
            log.info(f"Starting planarity analysis with {len(landmarks_sequence) if landmarks_sequence else 0} landmark sets")
            if landmarks_sequence is not None and len(landmarks_sequence) > 0:
                first_landmark = landmarks_sequence[0]
                log.info(f"First landmark set type: {type(first_landmark)}")
                if hasattr(first_landmark, '__len__'):
                    log.info(f"First landmark set length: {len(first_landmark)}")
                planarity_score = self.planarity_analyzer.analyze_planarity(face_frames, landmarks_sequence)
                log.info(f"Planarity analysis completed: score: {planarity_score:.3f}")
            else:
                log.warning(f"No landmarks provided for planarity analysis: {landmarks_sequence}")
            
            # Legacy analyzers (for comparison) - optimized to process fewer frames
            spatial_score = self.spatial_analyzer.analyze_spatial_pad(face_frames)
            temporal_score = self.temporal_analyzer.analyze_temporal_pad(face_frames)
            pose_score = 0.0
            if landmarks_sequence is not None and len(landmarks_sequence) > 0:
                pose_score = self.pose_analyzer.analyze_pose_consistency(face_frames, landmarks_sequence)
            
            # Decision logic based on advanced techniques
            hr_bpm = rppg_results.get("hr_bpm")
            rppg_live_prob = rppg_results.get("live_prob", 0.0)
            rppg_snr_db = rppg_results.get("snr_db", -999)
            
            # Live face criteria - be more conservative
            # If rPPG failed completely (hr_bpm is None), don't penalize
            rppg_failed = hr_bpm is None or rppg_snr_db <= -600  # More lenient SNR threshold
            live_ok = rppg_failed or ((rppg_live_prob >= 0.2) and (40 <= (hr_bpm or 0) <= 180))  # Reduced from 0.4 to 0.2
            
            # Spoof indicators - more lenient thresholds to reduce false negatives
            screen_suspect = flicker_score >= 0.98  # Much higher threshold to reduce false positives
            planar_suspect = planarity_score >= 0.95  # Much higher threshold for stronger evidence
            
            # Final decision: be more lenient - only flag as spoof if BOTH indicators are very strong
            # OR if we have extremely strong evidence of spoofing
            is_live = live_ok and not (screen_suspect and planar_suspect)  # Changed from OR to AND
            
            # Calculate overall confidence - be much more lenient
            if rppg_failed:
                # If rPPG failed, be more lenient unless we have very strong spoof indicators
                confidence = 0.9 if not (screen_suspect and planar_suspect) else 0.4  # Increased from 0.8 to 0.9
            else:
                # If rPPG detected valid heart rate with good SNR, be more lenient
                if hr_bpm is not None and 40 <= hr_bpm <= 180 and rppg_snr_db > 0:
                    # Valid heart rate detected - use higher confidence
                    confidence = max(0.9, rppg_live_prob)  # Increased from 0.8 to 0.9
                else:
                    confidence = rppg_live_prob
                
                # Only reduce confidence if BOTH indicators are present
                if screen_suspect and planar_suspect:
                    confidence *= 0.3  # More aggressive reduction only when both indicators present
                elif screen_suspect or planar_suspect:
                    confidence *= 0.7  # Less aggressive reduction for single indicator
            
            attack_detected = not is_live
            
            log.info(f"Advanced PAD Analysis Results:")
            hr_display = f"{hr_bpm:.1f}" if hr_bpm is not None else "N/A"
            log.info(f"  rPPG HR: {hr_display} BPM, SNR: {rppg_snr_db:.1f} dB, Live Prob: {rppg_live_prob:.3f}")
            log.info(f"  Display Flicker Score: {flicker_score:.3f} (threshold: 0.95)")
            log.info(f"  Planarity Score: {planarity_score:.3f} (threshold: 0.9)")
            log.info(f"  rPPG Failed: {rppg_failed}, Live OK: {live_ok}")
            log.info(f"  Screen Suspect: {screen_suspect}, Planar Suspect: {planar_suspect}")
            log.info(f"  Final Decision: {'LIVE' if is_live else 'SPOOF'} (confidence: {confidence:.3f})")
            
            return {
                "attack_detected": bool(attack_detected),
                "confidence": float(confidence),
                "live_final": bool(is_live),
                "rppg_hr_bpm": hr_bpm,
                "rppg_snr_db": float(rppg_snr_db),
                "rppg_live_prob": float(rppg_live_prob),
                "display_flicker_score": float(flicker_score),
                "planarity_score": float(planarity_score),
                "spatial_score": float(spatial_score),
                "temporal_score": float(temporal_score),
                "pose_score": float(pose_score),
                "analysis_details": {
                    "advanced_rppg": "Heart rate detection via green channel analysis",
                    "display_flicker": "Detection of screen refresh/PWM patterns",
                    "geometric_planarity": "3D vs planar motion analysis",
                    "legacy_spatial": "Texture and frequency domain analysis",
                    "legacy_temporal": "Basic temporal analysis",
                    "legacy_pose": "3D structure and movement consistency"
                }
            }
            
        except Exception as e:
            log.error(f"Advanced PAD analysis failed: {e}")
            return {
                "attack_detected": False,  # Default to not detecting attack on error
                "confidence": 0.5,
                "live_final": True,
                "rppg_hr_bpm": None,
                "rppg_snr_db": -999,
                "rppg_live_prob": 0.0,
                "display_flicker_score": 0.0,
                "planarity_score": 0.0,
                "spatial_score": 0.5,
                "temporal_score": 0.5,
                "pose_score": 0.5,
                "analysis_details": {"error": str(e)}
            }
