/* chat27.js */
var keyring = new openpgp.Keyring();
var refreshInterval;
var tabStack = [];

/* Caches plaintext messages to avoid decrypting same message multiple times within session */
var cache = {
    readMessages: {},
    unreadMessages: {}
};

$(document).ready(start);
function start(){
    var pair = getKeys();
    if(pair){
        messageToHTML(false, 'Keys found in localStorage ({0})'.format(pair.pub.nickname()), false);
        messageToHTML(false, 'Enter password to decrypt', false);
        input(decryptKeysIn(pair));
    } else {
        messageToHTML(false, 'No keys found in localStorage', false);
        messageToHTML(false, 'Generating keys', false);
        messageToHTML(false, 'Enter nickname', false);
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
            userIds: [{'name': nickname}],
            passphrase: pwd
        };

        openpgp.generateKey(options).then(function(keypair) {
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
            $('#messages').html('');
            $('#messages').hide();
            $('#title-right').show();
            hideInputForm();
            tab('friends');

            $.ajax({
                method: 'POST',
                'url': '/registerPubKey/',
                'data': {
                    'pub': keypair.publicKeyArmored
                }
            })
            .done(function(resp){
            })
            .fail(function(resp){
                console.log('Register public key failed')
            });
        });
    }
}

function sendChallenge(pair, toPub, text){
    if(text.length == 0){
        return;
    }
    /* Encrypt with their pub for transmission, own pub for storage */
    var signedMsg = openpgp.message.fromText(text).sign([pair.priv]);
    Promise.all([signedMsg.encrypt([toPub]), signedMsg.encrypt([pair.pub])]).then(function(r){
        var ctSend = r[0];
        var ctStorage = r[1];

        $.ajax({
            method: 'POST',
            'url': '/sendChallenge/',
            'data': {
                'fromPub': pair.pub.armor(),
                'toPub': toPub.armor(),
                'ciphertext': ctSend.armor()
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
    });
}

function sendResponse(pair, challenge, callback){
    openpgp.sign({
        'data': challenge,
        'privateKeys': pair.priv
    }).then(function(signature){
        $.ajax({
            method: 'POST',
            'url': '/sendResponse/',
            'data': {
                'fromPub': pair.pub.armor(),
                'challenge': challenge,
                'signature': signature.data.substring(signature.data.indexOf('-----BEGIN PGP SIGNATURE-----'))
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
    openpgp.sign({
        'data': challenge,
        'privateKeys': pair.priv
    }).then(function(signature){
        $.ajax({
            method: 'POST',
            url: '/refreshResponse/',
            data: {
                'pub': pair.pub.armor(),
                'challenge': challenge,
                'signature': signature.data.substring(signature.data.indexOf('-----BEGIN PGP SIGNATURE-----'))
                /* Detach signature */
            }
        })
        .done(function(data){
            var cts = [];
            var pts = [];   /* Promise array */
            var pubs = [];
            $.each(data.Messages, function(i,m){
                var fromPub = addPubKey(pair, data.FromPubs[i]);
                if(fromPub){
                    var ct = openpgp.message.readArmored(m);
                    cts.push(ct);
                    pts.push(ct.decrypt(pair.priv));
                    pubs.push(fromPub);
                    //TODO data.Dates[i];
                }
            });
            Promise.all(pts).then(function(r){
                $.each(r, function(i,pt){
                    if(pt && pt.verify([pubs[i]])[0].valid){
                        pt.cache(pubs[i], pair.pub, false);
                        cts[i].store(pubs[i], pair.pub, false);
                    }
                });
            });
        })
        .fail(function(resp){
            console.log('Refresh response failed');
        });
    })
}

function addPubKey(pair, pubStr){
    var numKeys = keyring.publicKeys.keys.length;
    var err = keyring.publicKeys.importKey(pubStr);
    if(err){
        return false;
    }
    keyring.store();
    var pub = openpgp.key.readArmored(pubStr).keys[0];
    if(numKeys != keyring.publicKeys.keys.length){
        addFriendHTML(pub);
        sendChallenge(pair, pub, "{0} has added {1}'s key".format(pair.pub.nickname(), pub.nickname()));
    }
    return pub;
}

function switchFriend(pair, friendFingerprint){
    $('#messages').html('');
    $('#title-mid').data('fingerprint', friendFingerprint);
    tab('messages');

    /* Check cache for plaintexts, else decrypt and initialize cache */
    var read = cache.readMessages[friendFingerprint];
    if(read){
        var merge = read.concat(cache.unreadMessages[friendFingerprint] || []);
        cache.readMessages[friendFingerprint] = merge;
        cache.unreadMessages[friendFingerprint] = [];
        for(var i=0; i < merge.length; i++){
            var m = merge[i];
            messageToHTML(m.fromFingerprint, m.text, m.outgoing);
        }
    } else {
        cache.unreadMessages[friendFingerprint] = [];   /* Avoid double printing these since theyre also stored */
        var msgs = getMessages().filter(function(m){
            return friendFingerprint == (m.outgoing ? m.toFingerprint : m.fromFingerprint);
        });

        var pts = msgs.map(function(m){
            return openpgp.message.readArmored(m.ciphertext).decrypt(pair.priv);
        });

        Promise.all(pts).then(function(r){
            $.each(r, function(i,pt){
                var fromPub = keyring.publicKeys.getForId(msgs[i].fromFingerprint);
                var toPub = keyring.publicKeys.getForId(msgs[i].toFingerprint);
                if(pt.verify([fromPub])[0].valid){
                    pt.cache(fromPub, toPub, msgs[i].outgoing);
                }
            });
        });
    }
}

/* Message is signed and encrypted */
window.openpgp.message.Message.prototype.store = function(fromPub, toPub, outgoing) {
    localStorage.setItem('chat27-messages', JSON.stringify(getMessages().concat([{
        'fromFingerprint': fromPub.primaryKey.fingerprint,
        'toFingerprint': toPub.primaryKey.fingerprint,
        'ciphertext': this.armor(),
        'outgoing': outgoing
    }])));
};

/* Message is signed and decrypted */
window.openpgp.message.Message.prototype.cache = function(fromPub, toPub, outgoing) {
    var m = {
        'fromFingerprint': fromPub.primaryKey.fingerprint,
        'toFingerprint': toPub.primaryKey.fingerprint,
        'text': this.getText(),
        'outgoing': outgoing
    }

    /* Print if currently chatting with friend */
    var friendFinger = outgoing ? toPub.primaryKey.fingerprint : fromPub.primaryKey.fingerprint;
    if($('#messages').css('display') != 'none' && $('#title-mid').data('fingerprint') == friendFinger){
        messageToHTML(fromPub.primaryKey.fingerprint, this.getText(), outgoing);
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

window.openpgp.key.Key.prototype.nickname = function(){
    return this.getUserIds()[0].slice(0,-3);
}

function getMessages(){
    return JSON.parse(localStorage.getItem('chat27-messages')) || [];
}

function addFriendHTML(pub){
    var fingerprint = pub.primaryKey.fingerprint;
    var color = hashToDarkColor(fingerprint);
    var html =
        '<div class="friend friend-box" fingerprint="{0}">'
        + '<div class="circle" style="background-color:#{1}"></div>'
        + '<span class="friend-name"> {2} </span>'
        + '<span class="unread"></span>'
        + '<span class="friend-info"></span>'
        + '</div><hr>';
    html = $(html.format(fingerprint, color, escapeHtml(pub.nickname())));
    $('#friends').append(html);
}

function messageToHTML(fingerprint, text, outgoing){
    var color = fingerprint ? hashToDarkColor(fingerprint) : '000000';
    var message = $('<span class="{0}"></span>'.format(outgoing ? 'bubble-right' : 'bubble-left'));
    message.css({
        'background-color': '#{0}'.format(color),
        'border-color': 'transparent #{0}'.format(color)
    });

    message.html(escapeHtml(text));
    $('#messages').append(message);
    var msgWindow = $('#chat-room-window');
    msgWindow.scrollTop(msgWindow.prop('scrollHeight'));
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

    card = card.format(pub.nickname(), fingerprint, pubStr);
}

function hideInputForm(){
    $('#input-form').hide();
    $('#chat-room-window').css('bottom', '10px');
}

function showInputForm(){
    $('#input-form').show();
    $('#chat-room-window').css('bottom', '90px');
}

function tab(to){
    var prev = tabStack[tabStack.length - 1];
    tabStack.push(to);
    setTitle(to);
    $('#' + prev).hide();
    $('#' + to).show();

    if(to == "messages"){
        showInputForm();
    } else if(prev == "messages"){
        hideInputForm();
    }

    if(to == 'settings'){
        $('#title-right').hide();
    }
    if(prev == 'friends'){
        $('#title-left').show();
    }
}

function back(){
    var prev = tabStack.pop();
    var to = tabStack[tabStack.length - 1];
    setTitle(to);
    $('#' + prev).hide();
    $('#' + to).show();

    if(to == "messages"){
        showInputForm();
    } else if(prev == "messages"){
        hideInputForm();
    }

    if(to == 'friends'){
        $('#title-left').hide();
    }
    if(prev == 'settings'){
        $('#title-right').show();
    }
}

function setTitle(to){
    var title = 'chat27';
    if(to == 'settings'){
        title = 'settings';
    } else if(to == 'messages'){
        title = keyring.publicKeys.getForId($('#title-mid').data('fingerprint')).nickname();
    }
    $('#title-mid').html(title);
}

function init(pair){
    input(chatIn(pair));
    keyring.publicKeys.keys.forEach(addFriendHTML);
    var addMeUrl = '{0}/add/{1}'.format(location.host, pair.pub.primaryKey.fingerprint);

    $('#menu-wrapper').show();
    $('#add-me').val(addMeUrl);
    $('#add-me').click(function(){
        $(this).select();
    });
    $('#add-me').change(function(){
        $(this).val(addMeUrl);
    });

    $('#title-left').on('click', back);
    $('#title-right').on('click', function(){
        tab('settings');
    });

    $('#refresh-time').on('change', function(){
        changeInterval(pair, $(this).val());
    });

    $('#friends').on('click', '.friend', function(e){
        if(e.target.className == 'friend-info'){
            friendInfo($(this).attr('fingerprint'));
        } else {
            switchFriend(pair, $(this).attr('fingerprint'));
            $(this).find('.unread').html('')
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
            if(pub && fingerprint != pub.primaryKey.fingerprint){
                console.log('fingerprint mismatch');//TODO
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
            $('#messages').html('');
            $('#messages').hide();
            $('#title-right').show();
            hideInputForm();
            tab('friends');
            $('#input-text').attr('type', 'text');
            input(chatIn(pair));
            init(pair);
        } else {
            messageToHTML(false, 'Incorrect password', false);
        }
    }
}

function nicknameIn(name){
    $('#input-text').attr('type', 'password');
    messageToHTML(false, 'Enter password to encrypt keys', false);
    input(generateKeys(name));
}

function chatIn(pair){
    return function(pt){
        $('#input-text').val('');
        var toPub = keyring.publicKeys.getForId($('#title-mid').data('fingerprint'));
        sendChallenge(pair, toPub, pt);
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
