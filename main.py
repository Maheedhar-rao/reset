from flask import Flask, request, jsonify, send_file, redirect, render_template_string
import requests
import os
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_ANON_KEY')

# Simple HTML template for error display
ERROR_TEMPLATE = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Error - CROC</title>
    <style>
        body { font-family: system-ui; display: flex; align-items: center; justify-content: center; min-height: 100vh; background: linear-gradient(180deg,#0f172a,#111827); margin: 0; }
        .error { background: white; padding: 40px; border-radius: 14px; max-width: 500px; text-align: center; }
        h1 { color: #dc2626; margin: 0 0 16px; }
        p { color: #374151; }
        a { color: #2563eb; }
    </style>
</head>
<body>
    <div class="error">
        <h1>{{ title }}</h1>
        <p>{{ message }}</p>
        <p><a href="/">Try again</a></p>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    """Handle both direct page access and token verification redirect"""
    token_hash = request.args.get('token')
    recovery_type = request.args.get('type')
    
    if token_hash and recovery_type == 'recovery':
        try:
            logger.info(f"=" * 50)
            logger.info(f"RECOVERY FLOW STARTED")
            logger.info(f"Token hash received: {token_hash}")
            logger.info(f"Token hash length: {len(token_hash)}")
            logger.info(f"=" * 50)
            
            headers = {
                'apikey': SUPABASE_KEY,
                'Content-Type': 'application/json'
            }
            
            # Verify the token hash with Supabase
            verify_url = f'{SUPABASE_URL}/auth/v1/verify'
            logger.info(f"Calling verify endpoint: {verify_url}")
            
            payload = {
                'token': token_hash,
                'type': 'recovery'
            }
            logger.info(f"Verify payload: {payload}")
            
            response = requests.post(
                verify_url,
                headers=headers,
                json=payload,
                timeout=10
            )
            
            logger.info(f"Verify response status: {response.status_code}")
            logger.info(f"Verify response headers: {dict(response.headers)}")
            logger.info(f"Verify response body: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Parsed JSON data: {data}")
                
                access_token = data.get('access_token')
                
                if access_token:
                    logger.info(f"Access token found: {access_token[:50]}...")
                    logger.info(f"Access token length: {len(access_token)}")
                    logger.info("Redirecting with access token in hash")
                    return redirect(f'/#access_token={access_token}&type=recovery', code=302)
                else:
                    logger.error(f"NO ACCESS TOKEN IN RESPONSE!")
                    logger.error(f"Full response data: {data}")
                    logger.error(f"Response keys: {data.keys()}")
                    return render_template_string(ERROR_TEMPLATE, 
                        title="Invalid Token",
                        message="Could not verify your reset link. Please request a new password reset."
                    )
            else:
                logger.error(f"Verify failed with status {response.status_code}")
                logger.error(f"Error response: {response.text}")
                return render_template_string(ERROR_TEMPLATE,
                    title="Verification Failed", 
                    message="Your reset link is invalid or has expired. Please request a new password reset."
                )
                
        except Exception as e:
            logger.error(f"Token exchange error: {str(e)}", exc_info=True)
            return render_template_string(ERROR_TEMPLATE,
                title="Error",
                message=f"An error occurred: {str(e)}"
            )
    
    # Serve the reset page
    return send_file('reset.html')

@app.route('/api/auth/user/reset-confirm', methods=['POST', 'OPTIONS'])
def reset_confirm():
    """Complete password reset using access token"""
    
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response
    
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('new_password')
        
        logger.info(f"Password reset request received")
        logger.info(f"Token present: {bool(token)}")
        logger.info(f"Token preview: {token[:50] if token else 'None'}...")
        
        if not token or not new_password:
            return jsonify({'error': 'Token and new password are required'}), 400
        
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        update_url = f'{SUPABASE_URL}/auth/v1/user'
        logger.info(f"Calling Supabase update endpoint: {update_url}")
        
        response = requests.put(
            update_url,
            headers=headers,
            json={'password': new_password},
            timeout=10
        )
        
        logger.info(f"Update response status: {response.status_code}")
        logger.info(f"Update response: {response.text[:200]}")
        
        if response.status_code == 200:
            result = jsonify({'message': 'Password updated successfully'})
            result.headers.add('Access-Control-Allow-Origin', '*')
            return result, 200
        else:
            error_data = response.json() if response.text else {}
            error_msg = error_data.get('msg') or error_data.get('error_description') or error_data.get('message') or 'Failed to update password'
            logger.error(f"Password update failed: {error_msg}")
            
            result = jsonify({'error': error_msg})
            result.headers.add('Access-Control-Allow-Origin', '*')
            return result, response.status_code
            
    except Exception as e:
        logger.error(f"Exception in reset_confirm: {str(e)}", exc_info=True)
        result = jsonify({'error': str(e)})
        result.headers.add('Access-Control-Allow-Origin', '*')
        return result, 500

@app.route('/api/auth/verify-token', methods=['POST'])
def verify_token():
    """Exchange token hash for JWT using pkce flow"""
    try:
        data = request.get_json()
        token_hash = data.get('token')
        token_type = data.get('type')
        
        logger.info(f"Token verification request")
        logger.info(f"Token hash: {token_hash[:50] if token_hash else 'None'}...")
        logger.info(f"Type: {token_type}")
        
        if not token_hash or token_type != 'recovery':
            return jsonify({'error': 'Invalid token or type'}), 400
        
        # For recovery tokens, we need to use the token hash directly as the JWT
        # But first, let's try to exchange it properly
        headers = {
            'apikey': SUPABASE_KEY,
            'Content-Type': 'application/json'
        }
        
        # Try using the token directly to get user info
        # The token hash from email can be used directly with Supabase
        test_headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f'Bearer {token_hash}',
            'Content-Type': 'application/json'
        }
        
        # Test if this token works
        test_response = requests.get(
            f'{SUPABASE_URL}/auth/v1/user',
            headers=test_headers,
            timeout=10
        )
        
        logger.info(f"Token test response: {test_response.status_code}")
        logger.info(f"Token test body: {test_response.text[:200]}")
        
        if test_response.status_code == 200:
            # Token works directly!
            logger.info("Token hash works as JWT directly")
            result = jsonify({'access_token': token_hash})
            result.headers.add('Access-Control-Allow-Origin', '*')
            return result, 200
        
        # If direct use doesn't work, the token might need to be exchanged
        # Let's return an error with details
        return jsonify({'error': f'Token verification failed. Status: {test_response.status_code}'}), 400
            
    except Exception as e:
        logger.error(f"Verify token error: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500
        
@app.route('/api/auth/user/reset-confirm-with-hash', methods=['POST', 'OPTIONS'])
def reset_confirm_with_hash():
    """Complete password reset using token hash from email"""
    
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response
    
    try:
        data = request.get_json()
        token_hash = data.get('token_hash')
        new_password = data.get('new_password')
        
        logger.info(f"Password reset with hash")
        logger.info(f"Token hash: {token_hash[:50] if token_hash else 'None'}...")
        
        if not token_hash or not new_password:
            return jsonify({'error': 'Token and new password are required'}), 400
        
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        # Use Supabase admin API to update password with token hash
        headers = {
            'apikey': SUPABASE_KEY,
            'Content-Type': 'application/json'
        }
        
        # First verify the token and get the user
        verify_url = f'{SUPABASE_URL}/auth/v1/user'
        verify_headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f'Bearer {token_hash}',
            'Content-Type': 'application/json'
        }
        
        logger.info(f"Verifying token hash...")
        verify_response = requests.get(verify_url, headers=verify_headers, timeout=10)
        logger.info(f"Verify response: {verify_response.status_code}")
        
        if verify_response.status_code != 200:
            logger.error(f"Token verification failed: {verify_response.text}")
            return jsonify({'error': 'Invalid or expired reset token'}), 401
        
        # Now update the password
        update_headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f'Bearer {token_hash}',
            'Content-Type': 'application/json'
        }
        
        update_url = f'{SUPABASE_URL}/auth/v1/user'
        logger.info(f"Updating password...")
        
        response = requests.put(
            update_url,
            headers=update_headers,
            json={'password': new_password},
            timeout=10
        )
        
        logger.info(f"Update response status: {response.status_code}")
        logger.info(f"Update response: {response.text[:200]}")
        
        if response.status_code == 200:
            result = jsonify({'message': 'Password updated successfully'})
            result.headers.add('Access-Control-Allow-Origin', '*')
            return result, 200
        else:
            error_data = response.json() if response.text else {}
            error_msg = error_data.get('msg') or error_data.get('error_description') or error_data.get('message') or 'Failed to update password'
            logger.error(f"Password update failed: {error_msg}")
            
            result = jsonify({'error': error_msg})
            result.headers.add('Access-Control-Allow-Origin', '*')
            return result, response.status_code
            
    except Exception as e:
        logger.error(f"Exception in reset_confirm_with_hash: {str(e)}", exc_info=True)
        result = jsonify({'error': str(e)})
        result.headers.add('Access-Control-Allow-Origin', '*')
        return result, 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
