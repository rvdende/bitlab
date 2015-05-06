var mailbot = {}

var net = require('net');
var MailParser = require("mailparser").MailParser;

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
//var domain = "launchlab.me";
var domain = mailbot.domain;

mailbot.server = net.createServer(function (socket) {
  socket.write('220 '+domain+' ESMTP LaunchLab\n')
  var incmail = {}
  var recievingdata = false;
  incmail.rcpt = [];
  incmail.message = "";

    socket.on('error', function() { console.log("mailbot protocol error"); });

    socket.on("data", function(data) {
        var datastr = data.toString();
        if (datastr.indexOf("EHLO") == 0) {
          incmail.client = datastr.slice(5,datastr.length)
          incmail.client = incmail.client.replace(/(\r\n|\n|\r)/gm," "); //CLEAN
          socket.write('250 Hello '+incmail.client+', whats up?\n')
        }

        if (datastr.indexOf("MAIL FROM:") == 0) {
          incmail.from = datastr.slice(datastr.indexOf("<")+1, datastr.indexOf(">"))
          incmail.from = incmail.from.replace(/(\r\n|\n|\r)/gm," ");
          socket.write('250 Ok\n')
        }

        if(datastr.indexOf("RCPT TO:") == 0) {
          var rcpt = datastr.slice(datastr.indexOf("<")+1, datastr.indexOf(">"))
          incmail.rcpt.push(rcpt);
          socket.write('250 Ok\n')  
        }

        if(datastr.indexOf("DATA") == 0) {
          recievingdata = true;
          socket.write('354 End data with <CR><LF>.<CR><LF>\n');
        }

        if (recievingdata == true) { incmail.message += datastr; }

        if (datastr.indexOf("\r\n.\r\n") >= 0) {
          recievingdata = false;
          socket.write('250 Ok: queued as 12345\n') 
          
          var mailparser = new MailParser();

          mailparser.on("headers", function(headers){
            console.log(headers.received);
          });

          mailparser.on("end", function(mail){
            //db.push(mail);
            console.log(mail);  // FINAL PARSED MAIL
          });
         
          mailparser.write(incmail.message);
          mailparser.end();
          console.log('recieved an email!')
        }

    if (datastr.indexOf("QUIT") == 0) {
          socket.write('221 Bye\n') 
          socket.end();

        }

    });
});

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

mailbot.sendemail = function (indata, callback) {
  var log = false;
  if (mailbot.debug) {
    if (mailbot.debug == true) {
      log = true;
    }
  }
  var email = {}
  email.date = new Date();

  email.rcptname = indata.rcptname;
  email.rcpt = indata.rcpt;
  email.from = indata.from;
  email.fromname = indata.fromname;
  
  email.formatteddate = mailbot.formatDateForEmail(email.date);

  email.subject = indata.subject;
  email.body = indata.body;

  if (log) { console.log(email.formatteddate); }

  email.fromdomain = email.from;
  email.fromdomain = email.fromdomain.slice(email.fromdomain.indexOf('@')+1, email.fromdomain.length);

  email.rcptdomain = email.rcpt;
  email.rcptdomain = email.rcptdomain.slice(email.rcptdomain.indexOf('@')+1, email.rcptdomain.length);

  email.data = 'From: "'+email.fromname+'" <'+email.from+'>\n';
  email.data += 'To: "'+email.rcptname+'" <'+email.rcpt+'>\n';
  email.data += 'Date: '+email.formatteddate+'\n';
  email.data += 'Subject: '+email.subject+'\n';
  email.data += 'Message-ID: <'+Date.now()+'@'+email.fromdomain+'>\n'
  email.data += '\n'+email.body+'\n\n\r\n.\r\n';


  var dns = require('dns');

  var mx = []

  var smtpserver = {}
  var sending = 0;
  var wait = 1;
  function sendemail(complete) {
    if (log) { console.log(mx[0].exchange) };
    var net = require('net');
    var client = net.connect({host: mx[0].exchange, port: 25}, function() { //'connect' listener
      if (log) { console.log('client connected'); }
      //client.write('world!\r\n');
    });

    client.on('data', function(data) {
      var datastr = data.toString();
      if (log) { console.log('S:'+datastr); }
      wait = 0;

      if (datastr.indexOf("220") == 0) { 
        smtpserver.host = datastr.slice(datastr.indexOf(' ')+1, datastr.indexOf('ESMTP')-1);
        var msg = 'HELO '+email.fromdomain+'\n'
        if (log) { console.log(msg); } 
        client.write(msg); 
        wait = 1;
      };

      if ((datastr.indexOf("250") == 0)&&(sending==0)&&(wait==0)) { 
        var msg = 'MAIL FROM: <'+email.from+'>\n'
        if (log) { console.log(msg); }
        client.write(msg); 
        sending = 1; wait = 1;
      }

      if ((datastr.indexOf("250") == 0) && (sending==1)&&(wait==0)) {
        var msg = "RCPT TO:<"+email.rcpt+">\n";
        if (log) { console.log(msg); }
        client.write(msg);
        sending=2; wait = 1;
      }

      if ((datastr.indexOf("250")== 0) && (sending==2)&&(wait==0)) {
        var msg = "DATA\n";
        if (log) { console.log(msg); }
        client.write(msg);
        sending=3; wait = 1;
      }    
      
      if ((datastr.indexOf("354")== 0) && (sending==3)&&(wait==0)) {
        var msg = email.data;
        if (log) { console.log(msg); }
        client.write(msg);      
        sending=4; wait = 1;
      } 

      if ((datastr.indexOf("250")== 0) && (sending==4)&&(wait==0)) {
        var msg = "QUIT\n"
        if (log) { console.log(msg); }
        client.write(msg);
        sending=5; wait = 1;
      }        

      if ((datastr.indexOf("221")== 0) && (sending==5)&&(wait==0)) {
        if (log) { console.log('END Successfully mailed it seems.'); }
        client.end();
      }        
    });
    
    client.on('end', function() {
      if (log) { console.log('client disconnected'); };
      complete();
    });
  }






    dns.resolveMx(email.rcptdomain, function(err, data) {
      if (data) {
        mx = data;
        sendemail( function () {
          // WHEN DONE
          callback({status:"sent"})
        });
      }  
    })

  
}


mailbot.days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
mailbot.months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

mailbot.formatDateForEmail = function (date) {
  var d = date;
  var formatted = mailbot.days[d.getUTCDay()] + ", "+d.getUTCDate()+" "+mailbot.months[d.getUTCMonth()]+" "+d.getUTCFullYear();
  formatted += " "+mailbot.padtwo(d.getUTCHours())+":"+mailbot.padtwo(d.getUTCMinutes())+":"+mailbot.padtwo(d.getUTCSeconds());


  var o = d.getTimezoneOffset();
  var H = mailbot.xPad(parseInt(Math.abs(o/60), 10), 0);
  var M = mailbot.xPad(Math.abs(o%60), 0);
  var timezone = (o>0?"-":"+") + H + M;


  formatted += " "+timezone
  return formatted;
}

mailbot.padtwo = function (input) {
  var ins = input.toString();
  if (ins.length == 1) {
    ins = "0"+ins;
  }
  return ins;
}

mailbot.xPad = function(x, pad, r)
{
  if(typeof r === "undefined") {
    r=10;
  }
  pad = pad.toString();
  for( ; parseInt(x, 10)<r && r>1; r/=10) {
    x = pad + x;
  }
  return x.toString();
}



module.exports = mailbot;
