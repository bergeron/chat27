/* chat27.js */
var keyring = new openpgp.Keyring();
var refreshInterval;

/* Caches plaintext messages to avoid decrypting same message multiple times within session */
var cache = {
	readMessages: {
		'chat27': []
	},
	unreadMessages: {}
};

$(document).ready(start);
function start(){
    var pair = getKeys();
    if(pair){
        var nickname = pair.pub.getPrimaryUser().user.userId.userid;
        chat27MessageYou('Keys found ({0})'.format(nickname));
        chat27MessageYou('Enter password to decrypt keys:');
        input(decryptKeysIn(pair));
    } else {
        chat27MessageYou('Generating keys');
        chat27MessageYou('Enter nickname:');
        input(nicknameIn);
    }
}

function getKeys(){
    try{
        return {
            'pub': keyring.privateKeys.keys[0].toPublic(),
            'priv': keyring.privateKeys.keys[0]
        }
    } catch (e){
        return false;
    }
}

function generateKeys(nickname){
    return function(pwd){
        var options = {
            numBits: 2048,
            userId: nickname,
            passphrase: pwd
        };
        
        openpgp.generateKeyPair(options).then(function(keypair) {
            $('#input-text').attr('type', 'text');
             
            keyring.publicKeys.importKey(keypair.publicKeyArmored);
            keyring.privateKeys.importKey(keypair.privateKeyArmored);
            keyring.store();

            var pair = {
                'pub': openpgp.key.readArmored(keypair.publicKeyArmored).keys[0],
                'priv': openpgp.key.readArmored(keypair.privateKeyArmored).keys[0]
            };
            
            pair.priv.decrypt(pwd);
            init(pair);
            chat27MessageYou('Login successful');
			
			$.ajax({
				method: 'POST',
				'url': '/registerPubKey/',
				'data': {
					'pub': keypair.publicKeyArmored
				}
			})
			.done(function(resp){})
			.fail(function(resp){
				console.log('Register public key failed')
			});
        });
    }
}

function sendChallenge(pair, toPub, text){
	/* Encrypt with their pub for transmission, own pub for storage */
	var signedMsg = openpgp.message.fromText(text).sign([pair.priv]);
	var ctSend = signedMsg.encrypt([toPub]).armor();
	var ctStorage = signedMsg.encrypt([pair.pub]);

	$.ajax({
		method: 'POST',
		'url': '/sendChallenge/',
		'data': {
			'fromPub': pair.pub.armor(),
			'toPub': toPub.armor(),
			'ciphertext': ctSend
		}
	})
	.done(function(challenge){
		sendResponse(pair, challenge, function(){
			ctStorage.store(pair.pub, toPub, true);
			signedMsg.cache(pair.pub, toPub, true);
		});
	})
	.fail(function(resp){
		console.log('Send challenge failed');
	}); 
}

function sendResponse(pair, challenge, callback){
	openpgp.signClearMessage(pair.priv, challenge).then(function(signature){
		console.log(signature);
		$.ajax({
			method: 'POST',
			'url': '/sendResponse/',
			'data': {
				'fromPub': pair.pub.armor(),
				'challenge': challenge,
				'signature': signature.substring(signature.indexOf('-----BEGIN PGP SIGNATURE-----'))
			}
		})
		.done(callback)
		.fail(function(resp){
			console.log('Send response failed');
		});
	})
}

function refreshChallenge(pair){
	$.ajax({
		method: 'POST',
		url: '/refreshChallenge/',
		data: {
			'pub': pair.pub.armor()
		}
	})
	.done(function(challenge) {
		refreshResponse(pair, challenge);
	})
	.fail(function(resp){
		console.log('Refresh challenge failed');
	});
}

function refreshResponse(pair, challenge){
	openpgp.signClearMessage(pair.priv, challenge).then(function(signature){
		$.ajax({
			method: 'POST',
			url: '/refreshResponse/',
			data: {
				'pub': pair.pub.armor(),
				'challenge': challenge,
				'signature': signature.substring(signature.indexOf('-----BEGIN PGP SIGNATURE-----'))	
			}
		})
		.done(function(data){
			for(var i=0; i < data.Messages.length; i++){
				var m = data.Messages[i];
				var fromPub = addPubKey(pair, data.FromPubs[i]);
				//var dt = data.Dates[i];
				if(fromPub){
					var ct = openpgp.message.readArmored(m);
					var pt = ct.decrypt(pair.priv);
					if(pt && pt.verify([fromPub])[0].valid){
						pt.cache(fromPub, pair.pub, false);
						ct.store(fromPub, pair.pub, false);
					}
				}
			}
		})
		.fail(function(resp){
			console.log('Refresh response failed');
		});
	})
}

function addPubKey(pair, pubStr){
    var numKeys = keyring.publicKeys.keys.length;
    var err = keyring.publicKeys.importKey(pubStr);
    if(err && err[0]){
        console.log(err[0]);
    } else {
        keyring.store();
        var pub = openpgp.key.readArmored(pubStr).keys[0];
        if(numKeys != keyring.publicKeys.keys.length){
            addFriendHTML(pub);
            sendChallenge(pair, pub, ' is ready to chat');
            chat27MessageYou("You added {0}'s key ({1})".format(pub.getPrimaryUser().user.userId.userid, pub.primaryKey.fingerprint));
        }
        return pub;
    }
}

function switchFriend(pair, friendFingerprint){
	$('#messages').html('');
    $('.friend-selected').find('.unread').html('');

	/* Check cache for plaintexts, else decrypt and initialize cache */
    var read = cache.readMessages[friendFingerprint];
    if(read){
        var merge = read.concat(cache.unreadMessages[friendFingerprint] || []);
        cache.readMessages[friendFingerprint] = merge;
        cache.unreadMessages[friendFingerprint] = [];
		for(var i=0; i < merge.length; i++){
			var m = merge[i];
            messageToHTML(m.fromFingerprint, m.text);
		}
	} else {
		cache.unreadMessages[friendFingerprint] = [];	/* Avoid double printing these since theyre also stored */
        var msgs = getMessages().filter(function(m){
			return friendFingerprint == (m.outgoing ? m.toFingerprint : m.fromFingerprint);
		});
		for(var i=0; i < msgs.length; i++){
			var m = msgs[i];
			var fromPub = keyring.publicKeys.getForId(m.fromFingerprint);
            var toPub = keyring.publicKeys.getForId(m.toFingerprint);
            var ct = openpgp.message.readArmored(m.ciphertext);
            var pt = ct.decrypt(pair.priv);
            if(pt.verify([fromPub])[0].valid){
                pt.cache(fromPub, toPub, m.outgoing);
            }
		}
    }
}

/* Message is signed-and-encrypted */
window.openpgp.message.Message.prototype.store = function(fromPub, toPub, outgoing) {
    localStorage.setItem('chat27-messages', JSON.stringify(getMessages().concat([{
        'fromFingerprint': fromPub.primaryKey.fingerprint,
        'toFingerprint': toPub.primaryKey.fingerprint,
        'ciphertext': this.armor(),
        'outgoing': outgoing
    }])));
};

/* Message is signed-and-decrypted */
window.openpgp.message.Message.prototype.cache = function(fromPub, toPub, outgoing) {
    var m = {
        'fromFingerprint': fromPub.primaryKey.fingerprint,
        'toFingerprint': toPub.primaryKey.fingerprint,
        'text': this.getText()
    }
    
    var friendFinger = outgoing ? toPub.primaryKey.fingerprint : fromPub.primaryKey.fingerprint;
    if(friendFinger == $('.friend-selected').attr('fingerprint')){
        messageToHTML(fromPub.primaryKey.fingerprint, this.getText());
        var pre = cache.readMessages[friendFinger] || [];
        cache.readMessages[friendFinger] = pre.concat([m]);
    } else {
        var pre = cache.unreadMessages[friendFinger] || [];
        cache.unreadMessages[friendFinger] = pre.concat([m]);
        $('.friend[fingerprint="{0}"]'.format(friendFinger))
			.find('.unread')
			.html('({0})'.format(pre.length + 1));
    }
};

function getMessages(){
    return JSON.parse(localStorage.getItem('chat27-messages')) || [];
}

function addFriendHTML(pub){
    var nickname = pub.getPrimaryUser().user.userId.userid;
	var fingerprint = pub.primaryKey.fingerprint;
    var color = hashToDarkColor(fingerprint);
    var html =
		'<div class="friend friend-box" fingerprint="{0}">'
		+ '<div class="circle" style="background-color:#{1}"></div>'
		+ '<span class="friend-name"> {2} </span>'
		+ '<span class="unread"></span>'
		+ '<span class="friend-info">i</span>'
		+ '</div><hr>';
    html = $(html.format(fingerprint, color, escapeHtml(nickname)));
    $('#friends-list').append(html);
}

function messageToHTML(fingerprint, text){
    var color = (fingerprint == 'chat27') ? 'black' : hashToDarkColor(fingerprint);
    var nickname = (fingerprint == 'chat27') ? 'chat27' : keyring.publicKeys.getForId(fingerprint).getPrimaryUser().user.userId.userid;
	
    var messageHTML = '' +
    '<div class="chat-msg">' +
        '<span class="nickname" style="color: #{0};"> {1} </span>'.format(color, escapeHtml(nickname)) +
        '<span class="msg-text">{0}</span>'.format(escapeHtml(text)) +
    '</div>';
    
    $('#messages').append(messageHTML);
    var msgWindow = $('#messages');
    msgWindow.scrollTop(msgWindow.prop('scrollHeight'));  
}

function chat27MessageYou(m){
    messageToHTML('chat27', m);
	cache.readMessages['chat27'].push({
		'fromFingerprint': 'chat27',
        'text': m
	});
}

function youMessageChat27(pair, m){
    switch (m.toLowerCase()) {
        case 'fingerprint':
            chat27MessageYou(pair.pub.primaryKey.fingerprint);
            break;
         case 'publickey':
            chat27MessageYou(pair.pub.armor());
            break;
         case 'keyring':
            chat27MessageYou(keyring.publicKeys.keys.length);
            break;
        case 'sign':
            break;
        case 'messages':
            chat27MessageYou(getMessages().length + ' messages');
            break;
        default:
            chat27MessageYou('COMMANDS: fingerprint publickey keyring sign messages');
            break;   
    }
}

function hashToDarkColor(fingerprint) {
    var i = parseInt(fingerprint, 16);
    var randDarkHex = function() {
        var hex = (i % 175).toString(16);
        while(hex.length < 2){
            hex = '0' + hex;
        }
        i = i / (Math.pow(10,i.toString().length/3));
        return hex;
    }
    return randDarkHex() + '' + randDarkHex() + '' + randDarkHex();
}

function friendInfo(fingerprint){
	var pub = keyring.publicKeys.getForId(fingerprint);
	var nickname = pub.getPrimaryUser().user.userId.userid;
	var pubStr =  pub.armor();

	var card = 
		'<div class="friend-info-card">'
		+ ''
		+ '{0}'
		+ '<br>'
		+ '{1}'
		+ '<br>'
		+ '{2}'
		+ '</div>';
	
	card = card.format(nickname, fingerprint, pubStr);
	$('#messages').html(card);
}

function init(pair){
    input(chatIn(pair));
    keyring.publicKeys.keys.forEach(addFriendHTML);
    
    $('#menu-wrapper').show();
	$('#add-me').val('localhost:11994/add/{0}'.format(pair.pub.primaryKey.fingerprint));
    $('#add-me').click(function(){
        $(this).select();
    });
	
	$('#refresh-time').on('change', function(){
		changeInterval(pair, $(this).val());
	});

    $('#friends-list').on('click', '.friend', function(e){
		if(e.target.className == 'friend-info'){
			friendInfo($(this).attr('fingerprint'));
		} else {
			$('.friend').removeClass('friend-selected');
			$(this).addClass('friend-selected');
			switchFriend(pair, $(this).attr('fingerprint'));
		}
    });

    $('#regenerate-keys').click(function(){
        if(confirm('Are you sure? You will lose all messages and friends.') == true) {
            keyring.clear();
            localStorage.clear();
            window.location.reload();
        }
    });
    
	if(window.location.pathname.indexOf("/add/") == 0){
		var fingerprint = window.location.pathname.substring(5);
		window.history.pushState('', '', '/');
		$.ajax({
			method: 'GET',
			'url': '/lookupPubKey/',
			'data': {
				'fingerprint': fingerprint
			}
		}).done(function(pubStr){
			var pub = addPubKey(pair, pubStr);
			if(fingerprint != pub.primaryKey.fingerprint){
				alert('fingerprint mismatch');//TODO
			}
		}).fail(function(resp){
		}); 
    }
	
    refreshChallenge(pair);
	changeInterval(pair, $('#refresh-time').val());
}

function changeInterval(pair, sec){
	sec = Math.max(1, sec);
	clearInterval(refreshInterval);
	refreshInterval = setInterval(function(){
        refreshChallenge(pair);
    }, sec * 1000);
}

function input(callback){
    $('#send-btn').off('click');
	$('#send-btn').click(function(){trigger();});
    $('#input-text').off('keypress');
    $('#input-text').keypress(function (e) {if (e.which == 13) {trigger();}});
    
    var trigger = function(){
        var i = $('#input-text').val();
        $('#input-text').val('');
        callback(i);
    }
}

function decryptKeysIn(pair){
    $('#input-text').attr('type',  'password');
    return function(pwd){
        if(pair.priv.decrypt(pwd)){
            chat27MessageYou('Login successful');
            $('#input-text').attr('type', 'text');
            input(chatIn(pair));
            init(pair);
        } else {
            chat27MessageYou('Incorrect password');
        }
    }
}

function nicknameIn(name){
    $('#input-text').attr('type', 'password');
    chat27MessageYou('Enter password to encrypt keys:');
    input(generateKeys(name));
}

function chatIn(pair){
    return function(pt){
        $('#input-text').val('');
        var toFinger = $('.friend-selected').attr('fingerprint');
        if(toFinger == 'chat27'){
            youMessageChat27(pair, pt);
        } else {
            var toPub = keyring.publicKeys.getForId(toFinger);
            sendChallenge(pair, toPub, pt);
        }
    }
}

function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

if (!String.prototype.format) {
    String.prototype.format = function() {
        var args = arguments;
        return this.replace(/{(\d+)}/g, function(match, number) {
            return typeof args[number] != 'undefined' ? args[number] : match;
        });
    };
}
