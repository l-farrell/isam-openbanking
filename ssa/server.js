const express = require('express')
const app = express()
const https = require('https');
const request = require('request');
var agentOptions;
var agent;

agentOptions = { host: 'isamruntime' , port: '443' , path: '/sps/authsvc/policy/ssa/' , rejectUnauthorized: false };

agent = new https.Agent(agentOptions);

var bodyParser = require('body-parser')

app.use(bodyParser.text({ type: "application/jwt" }));


var REGISTER = "https://isamruntime:443/sps/authsvc/policy/ssa/"
app.post('/', function (req, res) {
  console.log("Got req: " + req.body);
	request.post({url:REGISTER, agent: agent, form: {jwt: req.body}}, function optionalCallback(err, httpResponse, body) {
		if (err) {
			return console.error('POST failed:', err);
		}
		res.send(body)
	});
});

app.all('/eai', function (req, res) {
  console.log("Got eai req: " + JSON.stringify(req.headers));

  res.header('am-eai-ext-user-id', req.headers['cn']);
  res.sendStatus(200)
});

app.listen(8081)


