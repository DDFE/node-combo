'use strict';

var path = require('path'),
	fs = require('fs');

// check if the filepath is potentially malicious
function isMalicious(filepath) {
	var ext = path.extname(filepath);
	return ext !== '.css' && ext !== '.js' || filepath.indexOf('../') !== -1;
}

var ContentType = {
	css: 'text/css',
	js: 'application/javascript'
}

module.exports = function (options, PROD) {
	var root = options.root,
		useCache = options.cache,
		logger = options.log || console,
		//urlPrefix = options.prefix || '',
		lastHash, cached = {};
	return function (req, res, callback) {

		if (PROD && req.headers['if-modified-since']) {
			res.writeHead(304);
			res.end();
			callback && callback(null, {
				status: 304
			});
			return;
		}

		var i = req.url.indexOf('??'),
			j = req.url.indexOf('&'),
			url, ext, hash, files, contents = [], rs;
		if (~i) {
			url = ~j ? req.url.slice(i + 2, j) : req.url.slice(i + 2);
			ext = path.extname(url);
			if (ext)
				res.setHeader('Content-Type',ContentType[ext.slice(1)]);
			//res.type(ext.slice(1));
			if (~j) hash = req.url.slice(j + 1);
			if (hash !== lastHash) {
				lastHash = hash;
				cached = {};
			}
			if (PROD) {
				res.setHeader('Expires', 'Mon, 1 Jan 2100 00:00:00 GMT')
				res.setHeader('Last-Modified', 'Mon, 1 Jan 2100 00:00:00 GMT')
				res.setHeader('Cache-Control', 'public, max-age=' + 60 * 60 * 24 * 365);
				res.setHeader('Pragma', 'public');
			}
			files = url.split(',');
			files.forEach(function (file) {
				if (useCache && cached.hasOwnProperty(file)) {
					contents.push(cached[file]);
				} else if (isMalicious(file)) {
					logger.error('[combo] malicious file: ' + file);
				} else {
					var filePath = path.resolve(root, file), content;
					try {
						content = fs.readFileSync(filePath, 'utf-8');
						contents.push(content);
						if (useCache) {
							cached[file] = content;
						}
					} catch (e) {
						logger.error('[combo] cannot read file: ' + filePath + '\n', e.stack);
					}
				}
			});
			if (contents.length !== files.length) {
				res.writeHead(404);
				res.end();
				callback && callback({
					status: 404
				});
			} else {
				var chunk = contents.join('\n');
				res.writeHead(200);
				res.write(chunk);
				res.end();
				callback && callback({
					status: 200
				});
			}
		}
	};
};