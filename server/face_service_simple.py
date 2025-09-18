"""
Simplified face processing service for deployment
Uses face_recognition library instead of InsightFace for better compatibility
"""
import cv2
import numpy as np
import face_recognition
import logging
from typing import List, Tuple, Optional
import tempfile
import os

log = logging.getLogger(__name__)

class SimpleFaceService:
    def __init__(self):
        self.known_faces = {}  # Store face encodings in memory
        log.info("Simple face service initialized")
    
    def extract_frames_from_video(self, video_path: str, max_frames: int = 5) -> List[np.ndarray]:
        """Extract frames from video for face analysis"""
        frames = []
        cap = cv2.VideoCapture(video_path)
        
        if not cap.isOpened():
            raise ValueError(f"Could not open video file: {video_path}")
        
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        
        # Sample frames evenly throughout the video
        if frame_count > max_frames:
            frame_indices = np.linspace(0, frame_count - 1, max_frames, dtype=int)
        else:
            frame_indices = list(range(frame_count))
        
        for frame_idx in frame_indices:
            cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
            ret, frame = cap.read()
            if ret:
                # Convert BGR to RGB
                frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                frames.append(frame_rgb)
        
        cap.release()
        log.info(f"Extracted {len(frames)} frames from video")
        return frames
    
    def extract_face_encodings(self, frames: List[np.ndarray]) -> List[np.ndarray]:
        """Extract face encodings from frames using face_recognition"""
        encodings = []
        for i, frame in enumerate(frames):
            try:
                # Find face locations
                face_locations = face_recognition.face_locations(frame)
                
                if face_locations:
                    # Get face encodings
                    face_encodings = face_recognition.face_encodings(frame, face_locations)
                    
                    if face_encodings:
                        # Use the first (largest) face
                        encodings.append(face_encodings[0])
                        log.info(f"Extracted encoding from frame {i}")
                    else:
                        log.warning(f"No face encodings found in frame {i}")
                else:
                    log.warning(f"No faces detected in frame {i}")
                    
            except Exception as e:
                log.error(f"Error processing frame {i}: {e}")
                continue
        
        log.info(f"Extracted {len(encodings)} face encodings")
        return encodings
    
    def calculate_face_distance(self, encoding1: np.ndarray, encoding2: np.ndarray) -> float:
        """Calculate face distance (lower = more similar)"""
        return float(np.linalg.norm(encoding1 - encoding2))
    
    def find_best_match(self, query_encoding: np.ndarray, stored_encodings: List[np.ndarray], 
                       threshold: float = 0.5) -> Tuple[Optional[int], float]:
        """Find the best matching encoding from stored encodings"""
        best_match_idx = None
        best_distance = float('inf')
        
        for i, stored_encoding in enumerate(stored_encodings):
            distance = self.calculate_face_distance(query_encoding, stored_encoding)
            if distance < best_distance and distance <= threshold:
                best_distance = distance
                best_match_idx = i
        
        # Convert distance to similarity (0-1, higher = more similar)
        similarity = max(0, 1 - best_distance)
        return best_match_idx, similarity
    
    def process_video_file(self, video_path: str) -> List[np.ndarray]:
        """Complete pipeline: extract frames and encodings from video"""
        try:
            frames = self.extract_frames_from_video(video_path)
            encodings = self.extract_face_encodings(frames)
            return encodings
        except Exception as e:
            log.error(f"Error processing video file {video_path}: {e}")
            raise

# Global instance
simple_face_service = SimpleFaceService()
