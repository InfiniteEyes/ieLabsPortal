"""
Machine Learning module for cyber attack pattern recognition
Analyzes attack data to detect patterns, predict future attacks, 
and identify anomalies in attack behavior
"""

import pandas as pd
import numpy as np
from sklearn.cluster import DBSCAN, KMeans
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn import metrics
import joblib
import os
from datetime import datetime, timedelta
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

class AttackPatternAnalyzer:
    """Class for analyzing cyber attack patterns using machine learning techniques"""
    
    def __init__(self):
        """Initialize the analyzer with empty models"""
        self.clustering_model = None
        self.anomaly_model = None
        self.prediction_model = None
        self.vectorizer = None
        self.scaler = None
        self.encoder = None
        self.features = []
        self.categorical_features = ['attack_type', 'source_country', 'target_country', 'data_source']
        self.numerical_features = ['source_latitude', 'source_longitude', 'target_latitude', 'target_longitude']
        self.date_features = ['timestamp']
    
    def preprocess_data(self, df):
        """
        Preprocess attack data for machine learning
        
        Args:
            df: DataFrame containing attack data
            
        Returns:
            DataFrame with engineered features
        """
        if df.empty:
            logger.warning("Empty dataframe provided for preprocessing")
            return pd.DataFrame()
        
        # Make a copy to avoid modifying the original
        data = df.copy()
        
        # Convert timestamp to datetime if not already
        if 'timestamp' in data.columns and not pd.api.types.is_datetime64_dtype(data['timestamp']):
            data['timestamp'] = pd.to_datetime(data['timestamp'])
        
        # Feature engineering based on timestamp
        if 'timestamp' in data.columns:
            data['hour_of_day'] = data['timestamp'].dt.hour
            data['day_of_week'] = data['timestamp'].dt.dayofweek
            data['month'] = data['timestamp'].dt.month
            data['year'] = data['timestamp'].dt.year
            data['weekend'] = data['day_of_week'].apply(lambda x: 1 if x >= 5 else 0)
        
        # Fill missing values
        for col in self.numerical_features:
            if col in data.columns:
                data[col] = data[col].fillna(data[col].median())
        
        for col in self.categorical_features:
            if col in data.columns:
                data[col] = data[col].fillna('unknown')
        
        # Create attack frequency features
        if 'source_country' in data.columns:
            source_country_counts = data['source_country'].value_counts()
            data['source_country_frequency'] = data['source_country'].map(source_country_counts)
        
        if 'attack_type' in data.columns:
            attack_type_counts = data['attack_type'].value_counts()
            data['attack_type_frequency'] = data['attack_type'].map(attack_type_counts)
        
        # Store feature names for later use
        self.features = data.columns.tolist()
        
        return data
    
    def train_clustering_model(self, df):
        """
        Train a clustering model to identify attack patterns
        
        Args:
            df: DataFrame containing attack data
            
        Returns:
            Dictionary with clustering results
        """
        if df.empty:
            logger.warning("Empty dataframe provided for clustering")
            return {'success': False, 'message': 'No data provided'}
        
        try:
            # Preprocess data
            data = self.preprocess_data(df)
            
            # Select features for clustering
            feature_cols = [col for col in data.columns if col not in ['id', 'timestamp', 'created_at', 'updated_at']]
            
            # Prepare transformers for categorical and numerical features
            categorical_cols = [col for col in self.categorical_features if col in feature_cols]
            numerical_cols = [col for col in data.columns if col not in categorical_cols and col in feature_cols]
            
            preprocessor = ColumnTransformer(
                transformers=[
                    ('num', StandardScaler(), numerical_cols),
                    ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_cols)
                ])
            
            # Create clustering pipeline
            clustering_pipeline = Pipeline([
                ('preprocessor', preprocessor),
                ('clustering', DBSCAN(eps=0.5, min_samples=5))
            ])
            
            # Fit the model
            clustering_pipeline.fit(data[feature_cols])
            
            # Store the model
            self.clustering_model = clustering_pipeline
            
            # Get cluster labels
            labels = clustering_pipeline.named_steps['clustering'].labels_
            
            # Add cluster labels to the data
            data['cluster'] = labels
            
            # Count number of clusters (excluding noise)
            n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
            
            # Percentage of data points assigned to clusters vs. noise
            noise_percentage = np.sum(labels == -1) / len(labels) * 100 if len(labels) > 0 else 0
            
            # Save the model
            model_filename = os.path.join(MODEL_DIR, f'clustering_model_{datetime.now().strftime("%Y%m%d_%H%M%S")}.joblib')
            joblib.dump(clustering_pipeline, model_filename)
            
            return {
                'success': True,
                'n_clusters': n_clusters,
                'noise_percentage': noise_percentage,
                'cluster_counts': data['cluster'].value_counts().to_dict(),
                'model_filename': model_filename,
                'clustered_data': data
            }
        
        except Exception as e:
            logger.error(f"Error in clustering model training: {str(e)}")
            return {'success': False, 'message': str(e)}
    
    def train_anomaly_detection_model(self, df, contamination=0.05):
        """
        Train an anomaly detection model to identify unusual attack patterns
        
        Args:
            df: DataFrame containing attack data
            contamination: Expected proportion of anomalies in the data
            
        Returns:
            Dictionary with anomaly detection results
        """
        if df.empty:
            logger.warning("Empty dataframe provided for anomaly detection")
            return {'success': False, 'message': 'No data provided'}
        
        try:
            # Preprocess data
            data = self.preprocess_data(df)
            
            # Select features for anomaly detection
            feature_cols = [col for col in data.columns if col not in ['id', 'timestamp', 'created_at', 'updated_at']]
            
            # Prepare transformers for categorical and numerical features
            categorical_cols = [col for col in self.categorical_features if col in feature_cols]
            numerical_cols = [col for col in data.columns if col not in categorical_cols and col in feature_cols]
            
            preprocessor = ColumnTransformer(
                transformers=[
                    ('num', StandardScaler(), numerical_cols),
                    ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_cols)
                ])
            
            # Create anomaly detection pipeline
            anomaly_pipeline = Pipeline([
                ('preprocessor', preprocessor),
                ('anomaly_detector', IsolationForest(contamination=contamination, random_state=42))
            ])
            
            # Fit the model
            anomaly_pipeline.fit(data[feature_cols])
            
            # Store the model
            self.anomaly_model = anomaly_pipeline
            
            # Predict anomalies (1 for normal, -1 for anomalies)
            anomaly_scores = anomaly_pipeline.named_steps['anomaly_detector'].decision_function(data[feature_cols])
            predictions = anomaly_pipeline.named_steps['anomaly_detector'].predict(data[feature_cols])
            
            # Add anomaly scores and detection to the data
            data['anomaly_score'] = anomaly_scores
            data['is_anomaly'] = np.where(predictions == -1, 1, 0)
            
            # Calculate the percentage of anomalies found
            anomaly_percentage = np.sum(data['is_anomaly']) / len(data) * 100 if len(data) > 0 else 0
            
            # Save the model
            model_filename = os.path.join(MODEL_DIR, f'anomaly_model_{datetime.now().strftime("%Y%m%d_%H%M%S")}.joblib')
            joblib.dump(anomaly_pipeline, model_filename)
            
            # Get the most anomalous attacks
            anomalous_data = data[data['is_anomaly'] == 1].sort_values('anomaly_score')
            
            return {
                'success': True,
                'anomaly_percentage': anomaly_percentage,
                'anomaly_count': int(np.sum(data['is_anomaly'])),
                'model_filename': model_filename,
                'anomalous_data': anomalous_data,
                'data_with_scores': data
            }
        
        except Exception as e:
            logger.error(f"Error in anomaly detection model training: {str(e)}")
            return {'success': False, 'message': str(e)}
    
    def train_target_prediction_model(self, df):
        """
        Train a model to predict attack targets based on patterns
        
        Args:
            df: DataFrame containing attack data
            
        Returns:
            Dictionary with prediction model results
        """
        if df.empty:
            logger.warning("Empty dataframe provided for target prediction")
            return {'success': False, 'message': 'No data provided'}
        
        try:
            # Preprocess data
            data = self.preprocess_data(df)
            
            if 'target_country' not in data.columns:
                return {'success': False, 'message': 'Target country column is required for prediction'}
            
            # Features for training
            feature_cols = [col for col in data.columns if col not in ['id', 'target_country', 'timestamp', 'created_at', 'updated_at']]
            
            # Target variable
            target = 'target_country'
            
            # Prepare transformers for categorical and numerical features
            categorical_cols = [col for col in self.categorical_features if col in feature_cols]
            numerical_cols = [col for col in data.columns if col not in categorical_cols and col in feature_cols]
            
            preprocessor = ColumnTransformer(
                transformers=[
                    ('num', StandardScaler(), numerical_cols),
                    ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_cols)
                ])
            
            # Split data into training and testing sets
            X_train, X_test, y_train, y_test = train_test_split(
                data[feature_cols], data[target], test_size=0.2, random_state=42)
            
            # Create prediction pipeline
            prediction_pipeline = Pipeline([
                ('preprocessor', preprocessor),
                ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
            ])
            
            # Fit the model
            prediction_pipeline.fit(X_train, y_train)
            
            # Store the model
            self.prediction_model = prediction_pipeline
            
            # Evaluate model performance
            y_pred = prediction_pipeline.predict(X_test)
            accuracy = metrics.accuracy_score(y_test, y_pred)
            f1 = metrics.f1_score(y_test, y_pred, average='weighted')
            
            # Get feature importances
            feature_importances = None
            if hasattr(prediction_pipeline.named_steps['classifier'], 'feature_importances_'):
                # Get feature names from preprocessor
                cat_features = preprocessor.named_transformers_['cat'].get_feature_names_out(categorical_cols)
                all_features = list(numerical_cols) + list(cat_features)
                
                # Get importances
                importances = prediction_pipeline.named_steps['classifier'].feature_importances_
                
                # Match importances with feature names
                if len(importances) == len(all_features):
                    feature_importances = dict(zip(all_features, importances))
                    feature_importances = {k: v for k, v in sorted(feature_importances.items(), key=lambda item: item[1], reverse=True)[:10]}
            
            # Save the model
            model_filename = os.path.join(MODEL_DIR, f'prediction_model_{datetime.now().strftime("%Y%m%d_%H%M%S")}.joblib')
            joblib.dump(prediction_pipeline, model_filename)
            
            return {
                'success': True,
                'accuracy': accuracy,
                'f1_score': f1,
                'model_filename': model_filename,
                'feature_importances': feature_importances,
                'confusion_matrix': metrics.confusion_matrix(y_test, y_pred).tolist(),
                'classification_report': metrics.classification_report(y_test, y_pred, output_dict=True)
            }
        
        except Exception as e:
            logger.error(f"Error in target prediction model training: {str(e)}")
            return {'success': False, 'message': str(e)}
    
    def analyze_temporal_patterns(self, df):
        """
        Analyze temporal patterns in attack data
        
        Args:
            df: DataFrame containing attack data
            
        Returns:
            Dictionary with temporal pattern analysis
        """
        if df.empty:
            logger.warning("Empty dataframe provided for temporal analysis")
            return {'success': False, 'message': 'No data provided'}
        
        try:
            # Preprocess data
            data = self.preprocess_data(df)
            
            if 'timestamp' not in data.columns:
                return {'success': False, 'message': 'Timestamp column is required for temporal analysis'}
            
            # Ensure timestamp is datetime
            data['timestamp'] = pd.to_datetime(data['timestamp'])
            
            # Group by time periods
            hourly_pattern = data.groupby(data['timestamp'].dt.hour).size()
            daily_pattern = data.groupby(data['timestamp'].dt.dayofweek).size()
            monthly_pattern = data.groupby(data['timestamp'].dt.month).size()
            
            # Find peak attack times
            peak_hour = hourly_pattern.idxmax()
            peak_day = daily_pattern.idxmax()
            peak_month = monthly_pattern.idxmax()
            
            # Convert day number to name
            day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            peak_day_name = day_names[peak_day]
            
            # Convert month number to name
            month_names = ['January', 'February', 'March', 'April', 'May', 'June', 
                          'July', 'August', 'September', 'October', 'November', 'December']
            peak_month_name = month_names[peak_month-1]
            
            # Check for periodic patterns using FFT on daily data
            # Resample to daily frequency
            if data['timestamp'].min() + timedelta(days=14) <= data['timestamp'].max():
                daily_counts = data.resample('D', on='timestamp').size()
                
                # Compute FFT
                fft_values = np.fft.fft(daily_counts.values)
                fft_freq = np.fft.fftfreq(len(daily_counts))
                
                # Find dominant frequencies (excluding the DC component)
                dominant_periods = []
                for i in range(1, len(fft_freq)//2):
                    if abs(fft_values[i]) > 0.1 * max(abs(fft_values[1:len(fft_freq)//2])):
                        period = 1 / abs(fft_freq[i])
                        if period > 1:  # Only include periods longer than 1 day
                            dominant_periods.append((period, abs(fft_values[i])))
                
                # Sort by amplitude
                dominant_periods.sort(key=lambda x: x[1], reverse=True)
                
                # Extract top 3 periods
                top_periods = dominant_periods[:3]
            else:
                top_periods = []
            
            return {
                'success': True,
                'hourly_pattern': hourly_pattern.to_dict(),
                'daily_pattern': daily_pattern.to_dict(),
                'monthly_pattern': monthly_pattern.to_dict(),
                'peak_hour': peak_hour,
                'peak_day': peak_day_name,
                'peak_month': peak_month_name,
                'periodic_patterns': [{'period_days': round(p[0], 1), 'strength': float(p[1])} for p in top_periods]
            }
        
        except Exception as e:
            logger.error(f"Error in temporal pattern analysis: {str(e)}")
            return {'success': False, 'message': str(e)}
    
    def predict_attack_likelihood(self, source_country=None, attack_type=None, timeframe_days=7):
        """
        Predict likelihood of attacks based on trained model
        
        Args:
            source_country: Country of origin for the attack
            attack_type: Type of attack
            timeframe_days: Prediction timeframe in days
            
        Returns:
            Dictionary with attack likelihood predictions
        """
        if self.prediction_model is None:
            return {'success': False, 'message': 'Prediction model not trained'}
        
        try:
            # Create a sample for prediction
            sample = pd.DataFrame({
                'source_country': [source_country if source_country else 'unknown'],
                'attack_type': [attack_type if attack_type else 'unknown'],
                'timestamp': [datetime.now()]
            })
            
            # Preprocess the sample
            sample = self.preprocess_data(sample)
            
            # Make prediction
            if self.prediction_model:
                # Get features that the model was trained on
                prediction_features = [col for col in sample.columns if col in self.features and col != 'target_country']
                if not all(feature in sample.columns for feature in prediction_features):
                    return {'success': False, 'message': 'Sample data does not have all required features'}
                
                # Predict target countries
                probabilities = self.prediction_model.predict_proba(sample[prediction_features])
                
                # Get class names
                class_names = self.prediction_model.classes_
                
                # Create predictions dictionary
                predictions = {}
                for i, country in enumerate(class_names):
                    predictions[country] = float(probabilities[0][i])
                
                # Sort by probability
                predictions = {k: v for k, v in sorted(predictions.items(), key=lambda item: item[1], reverse=True)[:5]}
                
                return {
                    'success': True,
                    'predictions': predictions,
                    'timeframe_days': timeframe_days,
                    'source_country': source_country,
                    'attack_type': attack_type,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            else:
                return {'success': False, 'message': 'Prediction model not available'}
        
        except Exception as e:
            logger.error(f"Error in attack likelihood prediction: {str(e)}")
            return {'success': False, 'message': str(e)}
    
    def identify_attack_campaign(self, df, timespan_days=30, min_attacks=5):
        """
        Identify potential coordinated attack campaigns
        
        Args:
            df: DataFrame containing attack data
            timespan_days: Timespan to look for campaigns
            min_attacks: Minimum number of attacks to consider a campaign
            
        Returns:
            Dictionary with identified campaigns
        """
        if df.empty:
            logger.warning("Empty dataframe provided for campaign identification")
            return {'success': False, 'message': 'No data provided'}
        
        try:
            # Preprocess data
            data = self.preprocess_data(df)
            
            if 'timestamp' not in data.columns:
                return {'success': False, 'message': 'Timestamp column is required for campaign identification'}
            
            # Ensure timestamp is datetime
            data['timestamp'] = pd.to_datetime(data['timestamp'])
            
            # Set start date as the earliest date in the dataset minus timespan
            start_date = data['timestamp'].min() - timedelta(days=timespan_days)
            
            # Define campaigns based on similar source, target, and attack type in a given timespan
            campaigns = []
            
            # Group by source country, target country, and attack type
            if all(col in data.columns for col in ['source_country', 'target_country', 'attack_type']):
                grouped = data.groupby(['source_country', 'target_country', 'attack_type'])
                
                for (source, target, attack_type), group in grouped:
                    # Skip if group is too small
                    if len(group) < min_attacks:
                        continue
                    
                    # Sort by timestamp
                    group = group.sort_values('timestamp')
                    
                    # Check timespan - if first and last attack are within timespan_days
                    campaign_timespan = (group['timestamp'].max() - group['timestamp'].min()).days
                    if campaign_timespan <= timespan_days:
                        # Calculate attack frequency (attacks per day)
                        attack_frequency = len(group) / max(campaign_timespan, 1)
                        
                        campaigns.append({
                            'source_country': source,
                            'target_country': target,
                            'attack_type': attack_type,
                            'attack_count': len(group),
                            'start_date': group['timestamp'].min().strftime('%Y-%m-%d'),
                            'end_date': group['timestamp'].max().strftime('%Y-%m-%d'),
                            'timespan_days': campaign_timespan,
                            'attack_frequency': attack_frequency,
                            'data_sources': group['data_source'].unique().tolist() if 'data_source' in group.columns else [],
                            'severity': group['severity'].mode()[0] if 'severity' in group.columns and not group['severity'].isna().all() else 'Unknown'
                        })
            
            # Sort campaigns by attack count
            campaigns.sort(key=lambda x: x['attack_count'], reverse=True)
            
            return {
                'success': True,
                'campaigns': campaigns,
                'campaign_count': len(campaigns),
                'parameters': {
                    'timespan_days': timespan_days,
                    'min_attacks': min_attacks
                }
            }
        
        except Exception as e:
            logger.error(f"Error in attack campaign identification: {str(e)}")
            return {'success': False, 'message': str(e)}
    
    def load_model(self, model_type, model_path):
        """
        Load a previously trained model
        
        Args:
            model_type: Type of model ('clustering', 'anomaly', 'prediction')
            model_path: Path to the saved model file
            
        Returns:
            Boolean indicating success
        """
        try:
            if not os.path.exists(model_path):
                logger.error(f"Model file not found: {model_path}")
                return False
            
            # Load the model
            model = joblib.load(model_path)
            
            # Set the model
            if model_type == 'clustering':
                self.clustering_model = model
            elif model_type == 'anomaly':
                self.anomaly_model = model
            elif model_type == 'prediction':
                self.prediction_model = model
            else:
                logger.error(f"Unknown model type: {model_type}")
                return False
            
            logger.info(f"Successfully loaded {model_type} model from {model_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            return False
    
    def get_available_models(self):
        """
        Get a list of available trained models
        
        Returns:
            Dictionary with model filenames by type
        """
        try:
            if not os.path.exists(MODEL_DIR):
                return {'clustering': [], 'anomaly': [], 'prediction': []}
            
            # Get all .joblib files
            model_files = [f for f in os.listdir(MODEL_DIR) if f.endswith('.joblib')]
            
            # Organize by type
            clustering_models = [f for f in model_files if f.startswith('clustering_model_')]
            anomaly_models = [f for f in model_files if f.startswith('anomaly_model_')]
            prediction_models = [f for f in model_files if f.startswith('prediction_model_')]
            
            return {
                'clustering': clustering_models,
                'anomaly': anomaly_models,
                'prediction': prediction_models
            }
        
        except Exception as e:
            logger.error(f"Error getting available models: {str(e)}")
            return {'clustering': [], 'anomaly': [], 'prediction': []}


def train_models_on_attack_data(db_manager, timeframe=None):
    """
    Train machine learning models on attack data from the database
    
    Args:
        db_manager: DatabaseManager instance
        timeframe: Timeframe filter for attacks (e.g., 'Last 30 days')
        
    Returns:
        Dictionary with model training results
    """
    try:
        # Get attack data from the database
        attacks = db_manager.get_attacks(time_range=timeframe)
        
        # Convert to DataFrame
        attack_df = db_manager.attacks_to_dataframe(attacks)
        
        if attack_df.empty:
            return {'success': False, 'message': 'No attack data available'}
        
        # Create analyzer instance
        analyzer = AttackPatternAnalyzer()
        
        # Train models
        clustering_results = analyzer.train_clustering_model(attack_df)
        anomaly_results = analyzer.train_anomaly_detection_model(attack_df)
        prediction_results = analyzer.train_target_prediction_model(attack_df)
        temporal_results = analyzer.analyze_temporal_patterns(attack_df)
        campaign_results = analyzer.identify_attack_campaign(attack_df)
        
        # Return combined results
        return {
            'success': True,
            'data_size': len(attack_df),
            'timeframe': timeframe,
            'clustering': clustering_results,
            'anomaly': anomaly_results,
            'prediction': prediction_results,
            'temporal': temporal_results,
            'campaigns': campaign_results,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    except Exception as e:
        logger.error(f"Error training models: {str(e)}")
        return {'success': False, 'message': str(e)}