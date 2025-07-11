import os

import re

import logging

import string

import random

import hashlib

from urllib.parse import urlparse

from datetime import datetime, timedelta

from flask import Flask, render_template, request, jsonify

from flask_cors import CORS

from flask_limiter import Limiter

from flask_limiter.util import get_remote_address

import pyshorteners

from werkzeug.exceptions import BadRequest



# Configuration

class Config:

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'

    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

    HOST = os.environ.get('HOST', '0.0.0.0')

    PORT = int(os.environ.get('PORT', 5000))

    

    # Rate limiting

    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'memory://')

    

    # URLs autorisées (optionnel)

    ALLOWED_DOMAINS = os.environ.get('ALLOWED_DOMAINS', '').split(',') if os.environ.get('ALLOWED_DOMAINS') else []

    

    # Services de raccourcissement disponibles

    SHORTENER_SERVICES = {

        'tinyurl': {'name': 'TinyURL', 'avg_length': 19},

        'isgd': {'name': 'Is.gd', 'avg_length': 15},

        'osdb': {'name': 'OSDB', 'avg_length': 16},

        'dagd': {'name': 'Da.gd', 'avg_length': 14}

    }



app = Flask(__name__)

app.config.from_object(Config)



# Extensions

CORS(app)

limiter = Limiter(

    app=app,

    key_func=get_remote_address,

    default_limits=["500 per day", "100 per hour", "20 per minute"]

)



# Logging amélioré

logging.basicConfig(

    level=logging.INFO,

    format='%(asctime)s %(levelname)s %(name)s %(message)s',

    handlers=[

        logging.FileHandler('shortify.log'),

        logging.StreamHandler()

    ]

)

logger = logging.getLogger(__name__)



# Cache en mémoire pour les URLs fréquemment utilisées

url_cache = {}

stats_cache = {'total_links': 0, 'total_clicks': 0, 'daily_stats': {}}



def is_valid_url(url):

    """Validation d'URL améliorée avec sécurité renforcée"""

    try:

        # Pattern regex plus strict

        url_pattern = re.compile(

            r'^https?://'  # Protocole obligatoire

            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,}\.?|'  # Domaine

            r'localhost|'  # localhost autorisé

            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # Adresse IP

            r'(?::\d+)?'  # Port optionnel

            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

        

        if not url_pattern.match(url):

            return False, "Format d'URL invalide"

            

        parsed = urlparse(url)

        

        # Vérifications de sécurité

        if not parsed.netloc:

            return False, "Nom de domaine manquant"

            

        # Blocage des adresses locales/privées dangereuses

        dangerous_hosts = [

            'localhost', '127.0.0.1', '0.0.0.0', '::1',

            '10.', '172.16.', '192.168.', 'file://', 'ftp://'

        ]

        

        for dangerous in dangerous_hosts:

            if dangerous in url.lower():

                return False, "URL locale/privée non autorisée"

                

        # Blocage des protocoles dangereux

        if parsed.scheme not in ['http', 'https']:

            return False, "Protocole non autorisé"

            

        # Vérification des domaines autorisés

        if Config.ALLOWED_DOMAINS and parsed.netloc not in Config.ALLOWED_DOMAINS:

            return False, "Domaine non autorisé"

            

        # Vérification de la longueur du domaine

        if len(parsed.netloc) > 253:

            return False, "Nom de domaine trop long"

            

        return True, "URL valide"

        

    except Exception as e:

        logger.error(f"Erreur validation URL {url}: {e}")

        return False, f"Erreur de validation: {str(e)}"



def normalize_url(url):

    """Normalisation d'URL améliorée"""

    url = url.strip()

    

    # Supprime les espaces et caractères invisibles

    url = re.sub(r'\s+', '', url)

    

    # Ajoute HTTPS par défaut pour une meilleure sécurité

    if not url.startswith(('http://', 'https://')):

        url = 'https://' + url

    

    # Normalise les barres obliques multiples

    url = re.sub(r'([^:]\/)\/+', r'\1', url)

    

    return url



def get_shortest_service(url):

    """Détermine le meilleur service pour obtenir l'URL la plus courte"""

    services_by_length = sorted(

        Config.SHORTENER_SERVICES.items(),

        key=lambda x: x[1]['avg_length']

    )

    

    # Essaie les services dans l'ordre de longueur moyenne

    for service_name, service_info in services_by_length:

        try:

            s = pyshorteners.Shortener()

            service = getattr(s, service_name)

            short_url = service.short(url)

            

            if short_url and len(short_url) > 0:

                logger.info(f"Service {service_name} réussi: {len(short_url)} caractères")

                return short_url, service_name, len(short_url)

                

        except Exception as e:

            logger.warning(f"Service {service_name} échoué pour {url}: {e}")

            continue

    

    return None, None, 0



def shorten_with_service(url, preferred_service=None):

    """Raccourcit une URL avec le service spécifié ou le plus court disponible"""

    

    # Vérifie le cache d'abord

    cache_key = hashlib.md5(f"{url}_{preferred_service}".encode()).hexdigest()

    if cache_key in url_cache:

        cached = url_cache[cache_key]

        if datetime.now() - cached['timestamp'] < timedelta(hours=24):

            return cached['short_url'], cached['service'], cached['length']

    

    if preferred_service and preferred_service in Config.SHORTENER_SERVICES:

        # Essaie le service préféré d'abord

        try:

            s = pyshorteners.Shortener()

            service = getattr(s, preferred_service)

            short_url = service.short(url)

            

            if short_url:

                length = len(short_url)

                # Met en cache

                url_cache[cache_key] = {

                    'short_url': short_url,

                    'service': preferred_service,

                    'length': length,

                    'timestamp': datetime.now()

                }

                return short_url, preferred_service, length

                

        except Exception as e:

            logger.warning(f"Service préféré {preferred_service} échoué: {e}")

    

    # Fallback: trouve le service qui donne l'URL la plus courte

    return get_shortest_service(url)



def update_stats(original_length, short_length, service):

    """Met à jour les statistiques globales"""

    today = datetime.now().strftime('%Y-%m-%d')

    

    stats_cache['total_links'] += 1

    

    if today not in stats_cache['daily_stats']:

        stats_cache['daily_stats'][today] = {

            'links': 0,

            'saved_chars': 0,

            'services': {}

        }

    

    daily = stats_cache['daily_stats'][today]

    daily['links'] += 1

    daily['saved_chars'] += (original_length - short_length)

    daily['services'][service] = daily['services'].get(service, 0) + 1

    

    # Garde seulement les 30 derniers jours

    if len(stats_cache['daily_stats']) > 30:

        oldest_date = min(stats_cache['daily_stats'].keys())

        del stats_cache['daily_stats'][oldest_date]



@app.route('/')

def index():

    """Page d'accueil avec interface magnifique"""

    return render_template('index.html')



@app.route('/health')

def health_check():

    """Health check amélioré avec plus d'informations"""

    return jsonify({

        'status': 'healthy',

        'service': 'shortify-link',

        'version': '2.0.0',

        'uptime': 'running',

        'features': list(Config.SHORTENER_SERVICES.keys()),

        'total_links': stats_cache['total_links'],

        'cache_size': len(url_cache)

    })



@app.route('/services')

def get_services():

    """Retourne la liste des services disponibles"""

    return jsonify({

        'services': Config.SHORTENER_SERVICES,

        'default': 'isgd'  # Service par défaut (le plus court)

    })



@app.route('/stats')

def get_stats():

    """Retourne les statistiques globales"""

    today = datetime.now().strftime('%Y-%m-%d')

    today_stats = stats_cache['daily_stats'].get(today, {

        'links': 0,

        'saved_chars': 0,

        'services': {}

    })

    

    return jsonify({

        'total_links': stats_cache['total_links'],

        'today_links': today_stats['links'],

        'today_saved_chars': today_stats['saved_chars'],

        'popular_services': today_stats['services'],

        'daily_history': stats_cache['daily_stats']

    })



@app.route('/shorten', methods=['POST'])

@limiter.limit("10 per minute")

def shorten():

    """Raccourcit une URL avec le système ultra-performant"""

    try:

        # Validation des données d'entrée

        if not request.is_json:

            raise BadRequest("Content-Type doit être application/json")

            

        data = request.get_json()

        if not data:

            raise BadRequest("Données JSON invalides")

            

        url = data.get('url', '').strip()

        preferred_service = data.get('service', 'isgd')  # Service par défaut

        

        # Validation URL

        if not url:

            return jsonify({

                'success': False,

                'error': 'URL obligatoire',

                'code': 'URL_REQUIRED'

            }), 400

            

        if len(url) > 2000:

            return jsonify({

                'success': False,

                'error': 'URL trop longue (max 2000 caractères)',

                'code': 'URL_TOO_LONG'

            }), 400

        

        # Normalisation et validation

        normalized_url = normalize_url(url)

        is_valid, validation_message = is_valid_url(normalized_url)

        

        if not is_valid:

            return jsonify({

                'success': False,

                'error': f'URL invalide: {validation_message}',

                'code': 'INVALID_URL'

            }), 400

        

        # Raccourcissement avec le système intelligent

        try:

            short_url, service_used, short_length = shorten_with_service(

                normalized_url, preferred_service

            )

            

            if not short_url:

                return jsonify({

                    'success': False,

                    'error': 'Tous les services de raccourcissement sont temporairement indisponibles',

                    'code': 'ALL_SERVICES_DOWN'

                }), 503

            

            # Calcul des statistiques

            original_length = len(normalized_url)

            chars_saved = original_length - short_length

            reduction_percent = round((chars_saved / original_length) * 100, 1)

            

            # Mise à jour des statistiques

            update_stats(original_length, short_length, service_used)

            

            # Log du succès

            logger.info(

                f"URL raccourcie avec succès: {normalized_url} -> {short_url} "

                f"(service: {service_used}, réduction: {chars_saved} chars, {reduction_percent}%)"

            )

            

            return jsonify({

                'success': True,

                'original_url': normalized_url,

                'shortened_url': short_url,

                'service': service_used,

                'stats': {

                    'original_length': original_length,

                    'short_length': short_length,

                    'chars_saved': chars_saved,

                    'reduction_percent': reduction_percent

                },

                'metadata': {

                    'service_name': Config.SHORTENER_SERVICES[service_used]['name'],

                    'timestamp': datetime.now().isoformat()

                }

            })

            

        except Exception as e:

            logger.error(f"Erreur raccourcissement {normalized_url}: {str(e)}")

            return jsonify({

                'success': False,

                'error': 'Service de raccourcissement temporairement indisponible',

                'code': 'SERVICE_ERROR',

                'details': str(e) if Config.DEBUG else None

            }), 503

            

    except BadRequest as e:

        return jsonify({

            'success': False,

            'error': str(e),

            'code': 'BAD_REQUEST'

        }), 400

        

    except Exception as e:

        logger.error(f"Erreur interne dans /shorten: {str(e)}")

        return jsonify({

            'success': False,

            'error': 'Erreur interne du serveur',

            'code': 'INTERNAL_ERROR'

        }), 500



@app.route('/batch', methods=['POST'])

@limiter.limit("3 per minute")

def batch_shorten():

    """Raccourcit plusieurs URLs en une seule requête"""

    try:

        data = request.get_json()

        urls = data.get('urls', [])

        service = data.get('service', 'isgd')

        

        if not urls or len(urls) > 10:

            return jsonify({

                'success': False,

                'error': 'Entre 1 et 10 URLs autorisées',

                'code': 'INVALID_BATCH_SIZE'

            }), 400

        

        results = []

        for url in urls:

            normalized_url = normalize_url(url.strip())

            is_valid, validation_message = is_valid_url(normalized_url)

            

            if not is_valid:

                results.append({

                    'original_url': url,

                    'success': False,

                    'error': validation_message

                })

                continue

            

            try:

                short_url, service_used, short_length = shorten_with_service(

                    normalized_url, service

                )

                

                if short_url:

                    update_stats(len(normalized_url), short_length, service_used)

                    results.append({

                        'original_url': normalized_url,

                        'shortened_url': short_url,

                        'service': service_used,

                        'success': True

                    })

                else:

                    results.append({

                        'original_url': url,

                        'success': False,

                        'error': 'Service indisponible'

                    })

                    

            except Exception as e:

                results.append({

                    'original_url': url,

                    'success': False,

                    'error': str(e)

                })

        

        return jsonify({

            'success': True,

            'results': results,

            'total_processed': len(results),

            'successful': len([r for r in results if r.get('success')])

        })

        

    except Exception as e:

        logger.error(f"Erreur batch: {str(e)}")

        return jsonify({

            'success': False,

            'error': 'Erreur de traitement par lot',

            'code': 'BATCH_ERROR'

        }), 500



# Gestionnaires d'erreurs améliorés

@app.errorhandler(429)

def ratelimit_handler(e):

    """Gestion des erreurs de rate limiting avec plus d'infos"""

    return jsonify({

        'success': False,

        'error': 'Limite de requêtes dépassée. Veuillez patienter.',

        'code': 'RATE_LIMIT_EXCEEDED',

        'retry_after': getattr(e, 'retry_after', 60),

        'limit_info': {

            'daily': '500 requêtes/jour',

            'hourly': '100 requêtes/heure',

            'minute': '20 requêtes/minute'

        }

    }), 429



@app.errorhandler(404)

def not_found(e):

    """Gestion des erreurs 404 avec suggestions"""

    return jsonify({

        'success': False,

        'error': 'Endpoint non trouvé',

        'code': 'NOT_FOUND',

        'available_endpoints': [

            '/shorten (POST) - Raccourcir une URL',

            '/batch (POST) - Raccourcir plusieurs URLs',

            '/stats (GET) - Statistiques',

            '/services (GET) - Services disponibles',

            '/health (GET) - État du service'

        ]

    }), 404



@app.errorhandler(500)

def internal_error(e):

    """Gestion des erreurs 500 avec logging"""

    error_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]

    logger.error(f"Erreur 500 [ID: {error_id}]: {str(e)}")

    

    return jsonify({

        'success': False,

        'error': 'Erreur interne du serveur',

        'code': 'INTERNAL_ERROR',

        'error_id': error_id,

        'message': 'Contactez le support avec cet ID d\'erreur'

    }), 500



# Middleware pour les headers de sécurité

@app.after_request

def after_request(response):

    """Ajoute des headers de sécurité"""

    response.headers['X-Content-Type-Options'] = 'nosniff'

    response.headers['X-Frame-Options'] = 'DENY'

    response.headers['X-XSS-Protection'] = '1; mode=block'

    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    

    if not Config.DEBUG:

        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    

    return response



if __name__ == '__main__':

    logger.info("Démarrage de Shortify Link v2.0.0")

    logger.info(f"Services disponibles: {list(Config.SHORTENER_SERVICES.keys())}")

    logger.info(f"Mode debug: {Config.DEBUG}")

    

    app.run(

        host=Config.HOST,

        port=Config.PORT,

        debug=Config.DEBUG

    )