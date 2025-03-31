// 2021110900

function header_filter(r) {
    // do not waste CPU cycles when there are no Origin request header or no CORS configuration file present
    if (! ('http_origin' in r.variables)
	|| ! ('cors_config_file' in r.variables)
	|| ! r.variables.cors_config_file
	|| 0 === r.variables.cors_config_file.length) {
	return;
    }

    // read and parse external configuration file
    var fs = require('fs');
    var cors_configuration;
    try {
	cors_configuration = JSON.parse(fs.readFileSync(r.variables.cors_config_file));
    } catch (e) {
	r.warn('Cannot read CORS config file `' + r.variables.cors_config_file + "': " + e.message + ' << ' + e.name);
	return;
    }

    // ensure all values values are present
    if (! ('allowed_origins' in cors_configuration)) {
	cors_configuration.allowed_origins = '*';
    }
    if (! ('allowed_methods' in cors_configuration)) {
	cors_configuration.allowed_methods = [ 'OPTIONS', 'GET', 'POST', 'HEAD', 'PUT', 'DELETE' ];
    }
    if (! ('allowed_headers' in cors_configuration)) {
	cors_configuration.allowed_headers = 'mirror';
    }
    if (! ('exposed_headers' in cors_configuration)) {
	cors_configuration.exposed_headers = 'omit';
    }
    if (! ('max_age' in cors_configuration)) {
	cors_configuration.max_age = 7200;
    }
    if (! ('allow_credentials' in cors_configuration)) {
	cors_configuration.allow_credentials = true;
    }

    var access_control_allow_origin = '';
    if ('omit' === cors_configuration.allowed_origins) {
	return; // 'omit' effectively disables CORS processing
    } else if ('mirror' === cors_configuration.allowed_origins) {
	access_control_allow_origin = r.variables.http_origin;
    } else if ('*' === cors_configuration.allowed_origins) {
	access_control_allow_origin = '*';
    } else if (Array.isArray(cors_configuration.allowed_origins)) {
	for (let i in cors_configuration.allowed_origins) {
	    let re = new RegExp(cors_configuration.allowed_origins[i]);
	    if (re.test(r.variables.http_origin)) {
		access_control_allow_origin = r.variables.http_origin;
		break;
	    }
	}
    }
    if ('' === access_control_allow_origin) {
	return; // there were no matching allowed origins - stop CORS processing
    }

    // Access-Control-Allow-Origin
    r.headersOut['Access-Control-Allow-Origin'] = access_control_allow_origin;
    if ('Vary' in r.headersOut) {
	let elements = r.headersOut['Vary'].split(', ');
	elements.push('Origin');
	r.headersOut['Vary'] = elements.join(', ');
    } else {
	r.headersOut['Vary'] = 'Origin';
    }

    // Access-Control-Expose-Headers
    // exposed_headers := string 'omit', string '*', array of strings
    if ('*' === cors_configuration.exposed_headers) {
	r.headersOut['Access-Control-Expose-Headers'] = '*';
    } else if (Array.isArray(cors_configuration.exposed_headers)) {
	r.headersOut['Access-Control-Expose-Headers'] = cors_configuration.exposed_headers.join(', ');
    }

    // Access-Control-Allow-Credentials
    if ('omit' !== cors_configuration.allow_credentials) {
	if (cors_configuration.allow_credentials) {
	    r.headersOut['Access-Control-Allow-Credentials'] = 'true';
	} else {
	    r.headersOut['Access-Control-Allow-Credentials'] = 'false';
	}
    }

    r.variables.cors_is_valid_preflight_request = false;
    if ('OPTIONS' === r.method
	&& r.variables.http_access_control_request_method && 0 < r.variables.http_access_control_request_method.length
	&& r.variables.http_access_control_request_headers && 0 < r.variables.http_access_control_request_headers.length) {

	// signaling body_filter() to not send any content
	r.variables.cors_is_valid_preflight_request = true;

	r.status = 204;
	r.headersOut['Content-Length'] = 0;
	r.headersOut['Content-Type'] = 'text/plain; charset=utf-8';

	// Access-Control-Allow-Methods
	if ('mirror' === cors_configuration.allowed_methods) {
	    r.headersOut['Access-Control-Allow-Methods'] = r.variables.http_access_control_request_method;
	} else if ('omit' !== cors_configuration.allowed_methods && Array.isArray(cors_configuration.allowed_methods)) {
	    r.headersOut['Access-Control-Allow-Methods'] = cors_configuration.allowed_methods.join(', ');
	}

	// Access-Control-Max-Age
	if ('omit' !== cors_configuration.max_age) {
	    r.headersOut['Access-Control-Max-Age'] = cors_configuration.max_age;
	}

	// Access-Control-Allow-Headers
	if (r.variables.http_access_control_request_headers) {
	    if ('mirror' === cors_configuration.allowed_headers) {
		r.headersOut['Access-Control-Allow-Headers'] = r.variables.http_access_control_request_headers;
	    } else if ('*' === cors_configuration.allowed_headers) {
		r.headersOut['Access-Control-Allow-Headers'] = '*';
	    } else if (Array.isArray(cors_configuration.allowed_headers)) {
		r.headersOut['Access-Control-Allow-Headers'] = cors_configuration.allowed_headers.join(', ');
	    }
	} else {
	    if ('*' === cors_configuration.allowed_headers) {
		r.headersOut['Access-Control-Allow-Headers'] = '*';
	    } else if (Array.isArray(cors_configuration.allowed_headers)) {
		r.headersOut['Access-Control-Allow-Headers'] = cors_configuration.allowed_headers.join(', ');
	    }
	}
    }
}

//function body_filter(r, data, flags) {
//    // check if header_filter() thinks it is a valid preflight request
//    if (('cors_is_valid_preflight_request' in r.variables)
//	&& 'true' === r.variables.cors_is_valid_preflight_request) {
//	r.log("let's do it!");
//
//    }
//
//    // stop filtering this request
//    r.sendBuffer(data, flags);
//    r.done();
//}

//export default { header_filter, body_filter };
export default { header_filter };
