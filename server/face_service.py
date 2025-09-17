"""
Face processing service for extracting embeddings and performing verification
"""
import cv2
import numpy as np
import insightface
from insightface.app import FaceAnalysis
import logging
from typing import List, Tuple, Optional
import tempfile
import os

log = logging.getLogger(__name__)

class FaceService:
    def __init__(self):
        self.app = None
        self._initialized = False
        self._initialization_error = None
    
    def _initialize_model(self):
        """Initialize the InsightFace model"""
        try:
            log.info("Starting InsightFace model initialization...")
            # Initialize FaceAnalysis with default settings
            self.app = FaceAnalysis(name='buffalo_l', providers=['CPUExecutionProvider'])
            log.info("FaceAnalysis created, preparing model...")
            self.app.prepare(ctx_id=0, det_size=(640, 640))
            log.info("Face analysis model initialized successfully")
        except Exception as e:
            log.error(f"Failed to initialize face analysis model: {e}")
            log.error(f"Error type: {type(e).__name__}")
            import traceback
            log.error(f"Traceback: {traceback.format_exc()}")
            self._initialization_error = e
            raise
    
    def _ensure_initialized(self):
        """Ensure the model is initialized"""
        if self._initialized:
            return
        
        if self._initialization_error:
            raise self._initialization_error
        
        try:
            self._initialize_model()
            self._initialized = True
        except Exception as e:
            self._initialization_error = e
            raise
    
    def extract_frames_from_video(self, video_path: str, max_frames: int = 10) -> List[np.ndarray]:
        """Extract frames from video for face analysis"""
        frames = []
        
        # Try different backends for better WebM support
        backends = [
            cv2.CAP_FFMPEG,  # FFmpeg backend (best for WebM)
            cv2.CAP_ANY      # Default backend
        ]
        
        cap = None
        for backend in backends:
            try:
                cap = cv2.VideoCapture(video_path, backend)
                if cap.isOpened():
                    log.info(f"Successfully opened video with backend: {backend}")
                    break
                else:
                    cap.release()
            except Exception as e:
                log.warning(f"Backend {backend} failed: {e}")
                if cap:
                    cap.release()
        
        if not cap or not cap.isOpened():
            raise ValueError(f"Could not open video file: {video_path} with any backend")
        
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        
        log.info(f"Video info: {frame_count} frames, {fps} fps, {width}x{height}")
        
        # Handle invalid frame count (common with WebM files)
        if frame_count <= 0 or frame_count > 1000000:  # Sanity check
            log.warning(f"Invalid frame count ({frame_count}), using sequential reading")
            # Read frames sequentially until we get enough or reach end
            frame_indices = []
            current_frame = 0
            while len(frame_indices) < max_frames:
                cap.set(cv2.CAP_PROP_POS_FRAMES, current_frame)
                ret, test_frame = cap.read()
                if not ret:
                    break
                frame_indices.append(current_frame)
                current_frame += max(1, int(fps))  # Skip frames based on FPS
        else:
            # Sample frames evenly throughout the video
            if frame_count > max_frames:
                frame_indices = np.linspace(0, frame_count - 1, max_frames, dtype=int)
            else:
                frame_indices = list(range(frame_count))
        
        log.info(f"Extracting frames at indices: {frame_indices}")
        
        # Try indexed reading first, but fallback to sequential if it fails
        frames_extracted = 0
        if frame_indices:
            for frame_idx in frame_indices:
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
                ret, frame = cap.read()
                if ret:
                    # Convert BGR to RGB
                    frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    frames.append(frame_rgb)
                    frames_extracted += 1
                    log.info(f"Extracted frame {frame_idx}, shape: {frame_rgb.shape}")
                else:
                    log.warning(f"Failed to read frame {frame_idx}")
        
        # If indexed reading failed or extracted no frames, use sequential reading
        if frames_extracted == 0:
            log.info("Indexed reading failed, using sequential frame reading fallback")
            cap.release()  # Close and reopen for clean state
            cap = cv2.VideoCapture(video_path)
            
            frame_count = 0
            while len(frames) < max_frames:
                ret, frame = cap.read()
                if not ret:
                    log.info(f"Reached end of video at frame {frame_count}")
                    break
                
                # Convert BGR to RGB
                frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                frames.append(frame_rgb)
                log.info(f"Extracted sequential frame {frame_count}, shape: {frame_rgb.shape}")
                frame_count += 1
                
                # Skip some frames to get variety
                if frame_count % 5 == 0:  # Skip every 5th frame
                    for _ in range(3):
                        ret = cap.read()[0]  # Skip 3 frames
                        if not ret:
                            break
        
        cap.release()
        log.info(f"Extracted {len(frames)} frames from video")
        return frames
    
    def extract_face_embeddings(self, frames: List[np.ndarray]) -> List[np.ndarray]:
        """Extract face embeddings from frames"""
        log.info("Ensuring face service is initialized...")
        self._ensure_initialized()
        log.info("Face service initialized successfully")
        
        embeddings = []
        for i, frame in enumerate(frames):
            try:
                log.info(f"Processing frame {i}, shape: {frame.shape}")
                # Detect faces and extract embeddings
                faces = self.app.get(frame)
                log.info(f"Found {len(faces)} faces in frame {i}")
                
                if faces:
                    # Use the largest face (most likely to be the main subject)
                    largest_face = max(faces, key=lambda f: f.bbox[2] * f.bbox[3])
                    embedding = largest_face.embedding
                    embeddings.append(embedding)
                    log.info(f"Extracted embedding from frame {i}, face bbox: {largest_face.bbox}")
                else:
                    log.warning(f"No faces detected in frame {i}")
                    # Try with different detection size for this frame
                    try:
                        log.info(f"Trying smaller detection size for frame {i}")
                        faces_small = self.app.get(frame, det_size=(320, 320))
                        if faces_small:
                            largest_face = max(faces_small, key=lambda f: f.bbox[2] * f.bbox[3])
                            embedding = largest_face.embedding
                            embeddings.append(embedding)
                            log.info(f"Extracted embedding from frame {i} with smaller detection, face bbox: {largest_face.bbox}")
                        else:
                            log.warning(f"Still no faces detected in frame {i} with smaller detection")
                    except Exception as e2:
                        log.error(f"Error with smaller detection for frame {i}: {e2}")
                    
            except Exception as e:
                log.error(f"Error processing frame {i}: {e}")
                log.error(f"Error type: {type(e).__name__}")
                import traceback
                log.error(f"Traceback: {traceback.format_exc()}")
                continue
        
        log.info(f"Extracted {len(embeddings)} face embeddings")
        return embeddings
    
    def calculate_embedding_similarity(self, embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """Calculate cosine similarity between two embeddings"""
        # Normalize embeddings
        norm1 = np.linalg.norm(embedding1)
        norm2 = np.linalg.norm(embedding2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        # Calculate cosine similarity
        similarity = np.dot(embedding1, embedding2) / (norm1 * norm2)
        return float(similarity)
    
    def find_best_match(self, query_embedding: np.ndarray, stored_embeddings: List[np.ndarray], threshold: float = 0.6) -> Tuple[Optional[int], float]:
        """Find the best matching embedding from stored embeddings"""
        best_match_idx = None
        best_similarity = 0.0
        
        for i, stored_embedding in enumerate(stored_embeddings):
            similarity = self.calculate_embedding_similarity(query_embedding, stored_embedding)
            if similarity > best_similarity and similarity >= threshold:
                best_similarity = similarity
                best_match_idx = i
        
        return best_match_idx, best_similarity
    
    def process_video_file(self, video_path: str) -> List[np.ndarray]:
        """Complete pipeline: extract frames and embeddings from video"""
        try:
            log.info(f"Starting video processing for: {video_path}")
            frames = self.extract_frames_from_video(video_path)
            log.info(f"Extracted {len(frames)} frames")
            embeddings = self.extract_face_embeddings(frames)
            log.info(f"Extracted {len(embeddings)} embeddings")
            return embeddings
        except Exception as e:
            log.error(f"Error processing video file {video_path}: {e}")
            log.error(f"Error type: {type(e).__name__}")
            import traceback
            log.error(f"Traceback: {traceback.format_exc()}")
            raise

# Global instance
face_service = FaceService()
