var config = {
	production : true,	//enable for compression etc
	email : false,		//enable for email send/recieve
	port: 80,
	domain: "bitlab.io",
	sitename: "bitlab.io",
	adminemail: "rouan@8bo.org"
}

if (config.production == false) {
	config.port = 8000;
	config.domain = "127.0.0.1";
}

if (process.env.NODE_ENV == "production") {
	config.production = true;
	console.log("\nSTARTING in PRODUCTION mode. Enabled caching and emails.\n\n"); }
	else {
	console.log("\nSTARTING in DEVELOPMENT mode. Use for production:\n\tsudo NODE_ENV=production nodemon server\n\n"); }


var marked = require('marked');
var express = require('express')
  , http = require('http')
  , path = require('path')
  , reload = require('reload')

var serveStatic = require('serve-static')
var favicon = require('serve-favicon');
var bodyParser = require('body-parser')
var multer = require('multer');
var scrypt = require("./scrypt.js"); // modified https://github.com/tonyg/js-scrypt

var cookieParser = require('cookie-parser')
var session = require('cookie-session')
var compress = require('compression');
var swig  = require('swig');

// MAILBOT
var mailbot = require('./lib/mailbot')
mailbot.debug = true;
mailbot.domain = config.domain
if (config.email) {
	if (config.production == true) {
		console.log("email server: started")
		mailbot.server.listen(25, mailbot.domain);
	} else {
		console.log("email server: not started")
	}
}

// DATABASE
var mongojs = require("mongojs");
var databaseUrl = "bitlab"; 
var collections = ["posts",
					"users",
					"roles",
					"roles_users",
					"permissions",
					"permissions_users",
					"permissions_roles",
					"settings",
					"tags",
					"posts_tags",
					"permissions_apps",
					"apps",
					"app_settings",
					"app_fields",
					"mapnodes"
					];

var db = mongojs.connect(databaseUrl, collections);

var serveStatic = require('serve-static')
var favicon = require('serve-favicon');

var app = express()

var publicDir = path.join(__dirname, 'public')

app.use(session({
  keys: ['key1', 'key2'],
  secureProxy: false // if you do SSL outside of node
}))

app.use(bodyParser.json()); // for parsing application/json
app.use(bodyParser.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded
app.use(multer()); // for parsing multipart/form-data

app.use(compress());

//app.use(serveStatic(__dirname + '/public', {'index': ['default.html', 'default.htm']}))
app.use(express.static('public'));
app.use(favicon(__dirname + '/public/favicon.ico'));



app.engine('html', swig.renderFile);
app.set('view engine', 'html');
app.set('views', __dirname + '/views');
app.set('view cache', config.production);
if (config.production == true) {
	swig.setDefaults({ cache: 'memory' });
} else {
	swig.setDefaults({ cache: false });
}



///////////////////////////////////////////////////////////
// SIGNUP

app.get('/signup', function (req, res) {
    res.render('signup', {})
})

app.post('/signup', function (req, res) {
	//console.log(req.body);
	console.log("NEW SIGNUP")

	//encrypt pass
	var encrypted = scrypt.crypto_scrypt(scrypt.encode_utf8(req.body.email), scrypt.encode_utf8(req.body.pass), 128, 8, 1, 32);
	var encryptedhex = scrypt.to_hex(encrypted)

	var newuser = { email: req.body.email, secpass: encryptedhex, time: Date.now() };
	if (config.email == false) { newuser.verified = true;} //auto verify if email disabled

	db.users.find( {email: req.body.email}, function (err, resp) {

			if (resp.length == 0) {

			console.log("new unique signup");
			db.users.save( newuser, function (err, savedResp) {
				console.log("saved")
				console.log(savedResp._id);
				//var ObjectId = mongojs.ObjectId;

				req.session.email = req.body.email;
				req.session.secpass = encryptedhex;
				console.log(config.email);
				if (config.email == true) {
					console.log("MAIL ENABLED, DOING VERIFICATION");
					var email = {}
					email.from = "noreply@"+config.domain;
					email.fromname = config.sitename;
					email.rcpt = req.body.email;
					email.rcptname = "";
					email.subject = "Please verify your email address";

					if (config.port == 80) {
						email.body = "Please click on the link below to verify your email.\n http://"+config.domain+"/verify/"+savedResp._id+"\n\n\n";
					} else {
						email.body = "Please click on the link below to verify your email.\n http://"+config.domain+":"+config.port+"/verify/"+savedResp._id+"\n\n\n";
					}

					mailbot.sendemail(email, function (data)
					{
						console.log("EMAIL SENT")
					});
					res.send("verifyemail");
				} else {
					console.log("MAIL DISABLED, SKIPPING VERIFICATION");
					res.send("done")
				}


			} );

	      }

		if (resp.length > 0) {
			console.log("email exists! double signup?")
			res.send("exists")
		}
	})
	//
})

// EMAIL VERIFICATION

app.get('/verify/:id', function (req,res) {
	var ObjectId = mongojs.ObjectId;
	if (req.params.id.length == 24) {
		db.users.findOne( {"_id": ObjectId(req.params.id)}, function (err, resver) {
			if (resver) {
				resver.verified = true;
				db.users.update({"_id": ObjectId(req.params.id)}, resver);
				console.log("VERIFIED");
				req.session.email = resver.email;
				req.session.secpass = resver.secpass;
				res.render('verify', {});
			} else {
				console.log("VERIFICATION FAILED");
				res.render('error', {});
			}
		})
	} else {
		console.log("CODE TOO SHORT");
		res.render('error', {});
	}

});

///////////////////////////////////////////////////
// SIGNIN

app.get('/signin', function (req, res) {
  	res.render('signin', {})
});


app.post('/signin', function (req, res) {
	console.log("USER SIGNIN")

	//encrypt pass
	var encrypted = scrypt.crypto_scrypt(scrypt.encode_utf8(req.body.email), scrypt.encode_utf8(req.body.pass), 128, 8, 1, 32);
	var encryptedhex = scrypt.to_hex(encrypted);

	var signinuser = {email: req.body.email, secpass: encryptedhex};

	db.users.find( signinuser, function (err, resp) {
		if (resp.length == 0) {
			console.log("user not found");
			res.send("notfound")
		}
		if (resp.length > 0) {
			console.log("user found!")

			req.session.email = req.body.email;
			req.session.secpass = encryptedhex;
			//res.redirect("/");
			res.send("success")
		}
	})

})

///////////////////////////////////////////////////

app.get('/recover', function (req, res) {
	res.render("recover", {});
})

app.post('/recover', function (req, res) {
	console.log("USER RECOVER");
	db.users.findOne( {email: req.body.email}, function (err, resp) {
		console.log(resp);
		if (resp == null) {
			res.send("notfound");
		} else {
			//SEND EMAIL
			if (config.email == true) {

				var email = {}
				email.from = "noreply@"+config.domain;
				email.fromname = config.sitename;
				email.rcpt = req.body.email;
				email.rcptname = "";
				email.subject = "Account recovery";

				if (config.port == 80) {
					email.body = "Please click on the link below to set a new password.\n http://"+config.domain+"/newpass/"+resp._id+"\n\n\n";
				} else {
					email.body = "Please click on the link below to set a new password.\n http://"+config.domain+":"+config.port+"/newpass/"+resp._id+"\n\n\n";
				}

				mailbot.sendemail(email, function (data)
				{
					console.log("EMAIL SENT")
					res.send("success");
				});

			} else {
				res.send("emaildisabled")
			}
			//END EMAIL
		}

	})

	//
})

app.get('/newpass/:id', function (req, res) {
	console.log("NEWPASS FORM");
	var ObjectId = mongojs.ObjectId;
	if (req.params.id.length == 24) {
		db.users.findOne( {"_id": ObjectId(req.params.id)}, function (err, resver) {
			if (resver == null) {
				res.render("error", {});
			} else {
				console.log(resver);
				res.render("newpass", {});
			}

		});
	} else {
		res.render("error", {});
	}

})

app.post('/newpass/:id', function (req, res) {
	console.log("SET NEW PASSWORD");
	var ObjectId = mongojs.ObjectId;
	if (req.params.id.length == 24) {
		db.users.findOne( {"_id": ObjectId(req.params.id)}, function (err, resver) {
			if (resver == null) {
				res.send("error");
			} else {
				var encrypted = scrypt.crypto_scrypt(scrypt.encode_utf8(resver.email), scrypt.encode_utf8(req.body.pass), 128, 8, 1, 32);
				var encryptedhex = scrypt.to_hex(encrypted);
				resver.secpass = encryptedhex;
				db.users.update( {"_id": ObjectId(req.params.id)}, resver, function (err, resp) {
					req.session.email = resver.email;
					req.session.secpass = encryptedhex;
					res.send("success");
				})

			}

		});
	} else {
		res.render("error", {});
	}
})

///////////////////////////////////////////////////

app.get('/signout', function (req, res) {
  delete req.session.email;
  delete req.session.secpass;
  res.redirect('/');
});

//////////////////////////////////////////////////
// APP START BELOW
////////////////////////////////////////////////////////////

function newToOld(a,b) {
  if (a.published_at > b.published_at)
     return -1;
  if (a.published_at < b.published_at)
    return 1;
  return 0;
}

var getuser = function(req,res,callback) {
	var cookieuser = {email: req.session.email, secpass: req.session.secpass};
	db.users.findOne( cookieuser, function (err, resp) {
		callback(resp);
	});
}

app.get('/', function (req, res) 
{
  
	//load posts
	db.posts.find({"status":"published", "page": 0}, function (errp, posts) 
	{
		posts.sort(newToOld);
		
		for (var b in posts) {
			posts[b].html = marked(posts[b].markdown);
			var d = new Date(posts[b].published_at);
			posts[b].formatteddate = d.getFullYear() + "." + (d.getMonth()+1) + "." + d.getDate();
		}
		

		getuser(req,res, function (user) {
			res.render('home', {posts:posts, user:user})
		})
	})
	//load posts end

	/*

	var cookieuser = {email: req.session.email, secpass: req.session.secpass};

	db.users.find( cookieuser, function (err, resp) {

		if (resp) {
			if (resp.length == 0) {
				console.log("user not found. main");


			}
			if (resp.length > 0) {
				console.log("user found!")

				if (resp[0].verified) {
					res.render('home', { email: req.session.email })
				} else {
					if (config.email == true) {
						console.log("MAIL ENABLED, ENFORCING VERIFICATION");
						res.render('notverified', { email: req.session.email })
					} else {
						console.log("MAIL DISABLED, SKIPPING VERIFICATION");
						res.render('home', { email: req.session.email })
					}

				}

			}
		} else {
				console.log("user not found");
				res.render('home', {})
		}
	})
*/

})

///////////////////////////////////////////////////////////
// POSTS

app.get('/:slug', function (req,res,next) {

	/* db.tags.find({}, function (err, tags) {
		console.log(tags)
	}) */



	var slug = req.params.slug;
	db.posts.findOne({"slug":slug}, function (err, post) 
	{
		if (post == null) { next(); } else {
			db.posts_tags.find({"post_id":post.id}, function (err, posts_tags) 
			{
				var tagids = [];
				for (var t in posts_tags) { tagids.push(posts_tags[t].tag_id); }
				db.tags.find({"id": { "$in": tagids}}, function (err, tags) 
				{
					db.posts_tags.find({"tag_id":{ "$in": tagids}}, function (err, reltagids) 
					{
						var relpostids = [];
						for (var t in reltagids) { relpostids.push(reltagids[t].post_id); }
						db.posts.find({"id": {"$in":relpostids}}, function (err, relposts) 
						{
							relposts.sort(newToOld);

							//format date for relposts
							for (var a in relposts)
							{
								var d = new Date(relposts[a].published_at);
								relposts[a].formatteddate = d.getFullYear() + "." + (d.getMonth()+1) + "." + d.getDate();	
							}
							//format date for main post
							var d = new Date(post.published_at);
							post.formatteddate = d.getFullYear() + "." + (d.getMonth()+1) + "." + d.getDate();

							//remove main post from related posts.
							var relpostsClean = [];
							for (var a in relposts) {
								if (relposts[a].id != post.id) {
									relpostsClean.push(relposts[a]);
								}
							}

							post.html = marked(post.markdown);

							getuser(req,res, function (user) {
								res.render('post', {post:post, tags:tags, relposts:relpostsClean, user:user})
							})
							
						});
					});
				});				
			});
		}
	});
});


//////////////////////////////////////////////////



/*
app.get('/test', function (req, res) {
	//import json from ghost blog system.

	var fs = require('fs');
	fs.readFile( __dirname + '/bitlab-io.ghost.2015-04-01.json', function (err, data) {
	  if (err) {
	    throw err;
	  }

	  var indata 	 = data.toString();
	  var indatajson = JSON.parse(indata);

	  //console.log(indatajson.db[0].data.posts)

	  for (var a in indatajson.db[0].data) {
	  	//db.posts.save
		  for (var b in indatajson.db[0].data[a]) {
		  	db[a].save(indatajson.db[0].data[a][b]);
		  	console.log("saved an entry.")
		  }

	  }


	});

})


app.get('/import', function (req, res) {
	//import json from ghost blog system.

	var fs = require('fs');
	fs.readFile( __dirname + '/bitlab-io.ghost.2015-04-01.json', function (err, data) {
	  if (err) {
	    throw err;
	  }

	  var indata 	 = data.toString();
	  var indatajson = JSON.parse(indata);

	  //console.log(indatajson.db[0].data.posts)

	  for (var a in indatajson.db[0].data.posts) {
	  	db.posts.save(indatajson.db[0].data.posts[a]);
	  	console.log("saved an entry.")
	  }


	});

})
*/

///////////////////////////////////////////////////////////

app.get('/form', function (req, res) {

	db.users.find( {email: req.session.email, secpass: req.session.secpass}, function (err, resp) {
		if (resp.length == 0) {
			res.redirect('/signin', {})
		}
		if (resp.length == 1) {
			console.log("user found!")
			console.log(resp[0])
			res.render('app_form', resp[0])

		}
	})

})

app.post('/form', function (req, res) {
	console.log("FORM UPDATE")
	console.log(req.body);
	db.users.findOne( {email: req.session.email, secpass: req.session.secpass}, function (err, resp) {
		if (resp) {
			resp.form = req.body;
			console.log(resp)
			db.users.update( {email: req.session.email, secpass: req.session.secpass}, resp, function (err, respo) {
				res.send("success");
				console.log(respo);
			});
		}
	})

})

///////////////////////////////////////////////////////////

app.get('/search', function (req, res) {

	db.users.find( {email: req.session.email, secpass: req.session.secpass}, function (err, resp) {
		if (resp.length == 0) {
			res.redirect('/signin', {})
		}
		if (resp.length > 0) {
			console.log("user found!")
			res.render('app_search', { email: req.session.email })
		}
	})

})

app.post('/search', function (req, res) {
	console.log(req.body);
	db.users.find( req.body, function (err, resp) {
		for (var u in resp) {
			delete resp[u].secpass
		}
		var searchresult = {}
		searchresult.status = "success";
		searchresult.data = resp;
		console.log(searchresult);
		res.json(searchresult);
	})
})


///////////////////////////////////////////////////////////
// BTCMAP

app.get('/btcmap', function (req, res) 
{
	res.render('btcmap', { });
});

app.post('/btcmap/api/getnodes', function(req, res) {
	console.log("api getnodes")
	console.log(req.body);
	db.mapnodes.find( { "$and" : [ 
		{"lat" : { "$gte": parseFloat(req.body.lat[0]) }}, 
		{"lat" : { "$lte": parseFloat(req.body.lat[1]) }},
		{"lon" : { "$gte": parseFloat(req.body.lng[0]) }}, 
		{"lon" : { "$lte": parseFloat(req.body.lng[1]) }}
		] }, function (err, results) {
			res.json(results);
	});
	
})

app.post('/btcmap/api/addnode', function(req, res) {
	console.log("api addnode")
	req.body.timeadded = Date.now();
	req.body.lat = parseFloat(req.body.lat);
	req.body.lon = parseFloat(req.body.lon);
	console.log(req.body);
	db.mapnodes.save(req.body, function (err, result) {
		res.json({"result":"success"});	
	});
	
})

/* disabled after use. 
app.get('/osmdata', function (req, res) {
	//import coinmap info. run once.
	//data from http://overpass.osm.rambler.ru/cgi/interpreter?data=[out:json];(node[%22payment:bitcoin%22=yes];way[%22payment:bitcoin%22=yes];%3E;);out;
	
	var fs = require('fs');
	fs.readFile( __dirname + '/osm_btc.json', function (err, data) {
	  if (err) {
	    throw err;
	  }

	  var indata 	 = data.toString();
	  var indatajson = JSON.parse(indata);
	  var c = 0;
	  for (var i in indatajson.elements) 
	  {
	  	if (indatajson.elements[i].tags) 
	  	{
	  		if (indatajson.elements[i].tags["payment:bitcoin"]) 
	  		{
	  			if (indatajson.elements[i].type == "node") {
	  				c++;
	  				db.mapnodes.save(indatajson.elements[i]);
	  			}

	  		}
	  	}
	  }
	  console.log("imported!"+c);
	});
})
 */

///////////////////////////////////////////////////////////
// BLOG

app.post('/api/removepost', function (req, res) {
	getuser(req,res, function (user) {
		console.log(req.body);
		console.log(user);
		db.posts.remove(req.body, 1);
		res.json({"result":"success"});
	})	
})

app.get('/admin/', function (req, res) {
	res.render('admin', {});
})

app.get('/admin/editor', function (req, res) {
	res.render('admin_editor', {});
})

app.post('/admin/editor', function (req, res) {
	var post = req.body;
	db.posts.find({}, function(err, posts) {
		var lastid = 0;
		for (var p in posts) {
			if (posts[p].id > lastid) {
				lastid = posts[p].id;

			}
		}
		post.id = lastid+1;
		post.status = "published";		
		post.slug = post.title.toLowerCase().replace(/\s+/g, '-');
		post.page = 0;
		post.created_at = Date.now();
		post.updates_at = Date.now();
		post.published_at = Date.now();

		console.log(post);

		db.posts.save(post, function (err, dbreply) {
			res.end("success");		
		})
	});
	
})

/*
app.get('/makeadmin', function (req,res){
	//modifies the admin account to give admin rights.
	db.users.findOne({"email":config.adminemail}, function (err, user) {
		user.admin = true;
		db.users.update({"email":config.adminemail}, user, function (err2, admin) {
			res.end("done.")
		})
	})
})
*/

///////////////////////////////////////////////////////////

app.get('*', function(req, res){
  res.status(404).render("404", {});
});



var server = http.createServer(app)



server.listen(config.port, function(){
  console.log("Web server   : started on port " + config.port);
});
