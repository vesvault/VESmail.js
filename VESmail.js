
function VESmail(optns) {
    if (optns) for (var k in optns) this[k] = optns[k];
    return this;
}

VESmail.prototype.contentType = null;
VESmail.prototype.contentDisposition = null;
VESmail.prototype.boundary = null;
VESmail.prototype.filename = null;
VESmail.prototype.parts = null;
VESmail.prototype.headers = null;
VESmail.prototype.body = null;

VESmail.getHParams = function(h) {
    var vals = {};
    h.replace(/\;\s*([\w\-\.]+)\s*\=\s*((\"(([^\\\"]|\\.)*)\")|(\'(([^\\\']|\\.)*)\')|(([^\\\"\'\;\s]|\\.)*))/g, function(s, k, _v, dq, dv, _d1, sq, sv, _s1, b, _b1) {
	vals[k.toLowerCase()] = (sq ? sv : (dq ? dv : b)).replace(/\\(.)/g, '$1');
	return s;
    });
    return vals;
};

VESmail.getHVal = function(h) {
    return h.replace(/\;.*/s, '').replace(/\s/g, '').toLowerCase();
};

VESmail.prototype.newPart = function() {
    return new VESmail({vaultItem: this.vaultItem, pxchg: this.pxchg});
};

VESmail.prototype.decrypt = function(msg, partial) {
    var self = this;
    var m = msg.match(/^((\S+\s*\:[^\n]*(\n[\t ][^\n]*)*\n)*)(\r?\n)?(.*)$/s);
    var hdrs = m[1].match(/\S+\s*\:\s*[^\n]*(\n[\t ][^\n]*)*\n/sg);
    if (!hdrs) hdrs = [];
    var ps = [];
    var encd = false;
    this.headers = [];
    var p_hdrs = {};
    var e_hdrs = {};
    for (var i = 0; i < hdrs.length; i++) {
	var hdr = hdrs[i].replace(/\r$/, '');
	var h = hdr.match(/^(\S+)\s*\:\s*(.*?)(\r?\n)?$/s);
	var hk = h[1].toLowerCase();
	switch (hk) {
	    case 'content-type':
		var t = VESmail.getHVal(h[2]);
		if (t.match(/^application\/(vnd\.ves\.encrypted|x-ves-encrypted)$/)) encd = true;
		else {
		    if (!this.contentType) this.contentType = t;
		    if (t.match(/^multipart\//)) this.boundary = VESmail.getHParams(h[2]).boundary;
		    this.headers[p_hdrs[hk] = this.headers.length] = hdr;
		}
		break;
	    case 'content-disposition':
		if (!this.contentDisposition) this.contentDisposition = VESmail.getHVal(h[2]);
	    case 'subject':
	    case 'content-transfer-encoding':
		this.headers[p_hdrs[hk] = this.headers.length] = hdr;
		break;
	    case 'x-vesmail-header':
		self.headers.push(null);
		ps.push((function(idx) {
		    return self.decryptData(h[2]).then(function(hdrb) {
			var hdrd = libVES.Util.ByteArrayToString(hdrb);
			self.headers[idx] = hdrd + h[3];
			var hd = hdrd.match(/^(\S+)\s*\:\s*(.*?)(\r?\n)?$/s);
			var hkd = hd[1].toLowerCase();
			e_hdrs[hkd] = true;
			switch (hkd) {
			    case 'content-type':
				self.contentType = VESmail.getHVal(hd[2]);
				break;
			    case 'content-disposition':
				self.contentDisposition = VESmail.getHVal(hd[2]);
				self.filename = VESmail.getHParams(hd[2]).filename;
				break;
			    case 'content-id':
				var cid = hd[2].replace(/\;.*/s, '').replace(/\s/sg, '');
				var cidp = cid.match(/\<(.*)\>/s);
				self.contentID = cidp ? cidp[1] : cid;
				break;
			}
		    }).catch(function(e) {
			self.error = true;
		    });
		})(self.headers.length - 1));
		break;
	    case 'x-vesmail-id':
	    case 'x-vesmail-part':
		break;
	    case 'x-vesmail-xchg':
		try {
		    var xchg = JSON.parse(h[2]);
		    var pxchg = null;
		    if (!self.pxchg) self.pxchg = function() {
			if (!pxchg) pxchg = self.vaultItem.VES.me().then(function(me) {
			    return me.getId().then(function(uid) {
				var ks = [];
				for (var j = 0; j < xchg.length; j++) if (xchg[j][0] == uid) {
				    ks.push((function(vk) {
					return vk.unlock(xchg[j][2]).then(function(k) {
					    return vk.rekey();
					}).catch(function(e) {console.log(e);});
				    })(new libVES.VaultKey({id: xchg[j][1]}, self.vaultItem.VES)));
				}
				return Promise.all(ks);
			    });
			}).catch(function(e) {});
			return pxchg;
		    };
		} catch (e) {
		    console.log(e);
		}
		break;
	    default:
		this.headers.push(hdr);
		break;
	}
    }
    
    if (this.boundary) {
	this.parts = [];
	var rx = this.boundary.replace(/([^\w\-])/g, '\\$1');
	var idx = 0;
	var lastp = false;
	var ml = m[5].replace(new RegExp('(^|(.*?)\\r?\\n)--' + rx + '((--.*$)|.*?\\n)', 'sg'), function(s, _b, p, _o, e) {
	    if (idx > 0) (function(i) {
		ps.push(self.newPart().decrypt(p).then(function(part) {
		    self.parts[i] = part;
		    if (part.error) self.error = true;
		}));
	    })(idx - 1);
	    idx++;
	    if (e) lastp = true;
	    return "";
	});
	if (!lastp) (function(i) {
	    self.partial = true;
	    ps.push(self.newPart().decrypt(ml.replace(/[^\r\n]*$/s, ''), true).then(function(part) {
		self.parts[i] = part;
		if (part.error) self.error = true;
	    }));
	})(idx - 1);
    } else if (this.contentType == 'message/rfc822') {
	ps.push(self.newPart().decrypt(m[5]).then(function(part) {
	    self.parts = [part];
	    if (part.error) self.error = true;
	}));
    } else if (encd) {
	ps.push(self.decryptData(m[5], partial).then(function(body) {
	    self.body = new Blob([body], {type: self.contentType});
	    if (partial) self.partial = true;
	}).catch(function(e) {
	    self.error = true;
	}));
    }
    
    return Promise.all(ps).then(function() {
	for (var hk in p_hdrs) {
	    if (e_hdrs[hk]) {
		self.headers.splice(p_hdrs[hk], 1);
		for (var hk2 in p_hdrs) if (p_hdrs[hk2] > p_hdrs[hk]) p_hdrs[hk2]--;
	    }
	}
	if (!self.contentType) self.contentType = 'text/plain';
	return self;
    });
};

VESmail.prototype.decryptData = function(b64, partial) {
    var self = this;
    return this.vaultItem.get().catch(function(e) {
	if (!self.pxchg) throw e;
	return self.pxchg().then(function() {
	    return self.vaultItem.get();
	});
    }).then(function(ci) {
	return ci.decrypt(libVES.Util.B64ToByteArray(b64), !partial);
    });
};

VESmail.prototype.getHeaders = function() {
    var hdrs = {};
    for (var i = 0; i < this.headers.length; i++) if (this.headers[i]) {
	var m = this.headers[i].match(/^(\S+)\s*:\s*(.*?)\r?\n?$/s);
	hdrs[m[1].toLowerCase()] = m[2];
    }
    return hdrs;
};

VESmail.prototype.getString = function() {
    if (!this.body) return Promise.resolve(null);
    return this.body.text ? this.body.text() : this.body.arrayBuffer().then(function(buf) {
	return libVES.Util.ArrayBufferToString(buf);
    });
};

VESmail.prototype.getContent = function(type) {
    if (!this.parts) {
	if (this.contentType == type) return this.getString();
    } else {
	var i = 0;
	var fn = function(txt) {
	    if (txt != null) return txt;
	    if (this.parts[i]) return this.parts[i++].getContent(type).then(fn);
	}.bind(this);
	return fn(null);
	for (var i = 0; i < this.parts.length; i++) if (this.parts[i].contentType == type) return this.parts[i].getString();
	for (var i = 0; i < this.parts.length; i++) if (this.parts[i].parts) return this.parts[i].getContent(type);
    }
    return Promise.resolve(null);
};

VESmail.prototype.getAttachments = function() {
    var att = [];
    if (this.parts) for (var i = 0; i < this.parts.length; i++) att = att.concat(this.parts[i].getAttachments());
    else if (this.contentDisposition == 'attachment') att.push(this);
    return att;
};

VESmail.prototype.getUrl = function() {
    return this.body ? URL.createObjectURL(this.body) : null;
};

VESmail.prototype.getCIDs = function() {
    var rs = {};
    if (this.contentID) rs[this.contentID] = this;
    if (this.parts) for (var i = 0; i < this.parts.length; i++) {
	var r = this.parts[i].getCIDs();
	for (var cid in r) rs[cid] = r[cid];
    }
    return rs;
};
