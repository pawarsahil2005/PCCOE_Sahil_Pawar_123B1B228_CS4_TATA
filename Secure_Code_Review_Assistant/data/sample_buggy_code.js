// TEST INPUT ONLY — intentionally buggy. Do not execute.

const apiKey = "sk-live-js-secret-example";
const password = "letmein";
let gCache = {};
let gUsers = {};
let gConfig = {};

function render(userInput) {
  document.getElementById("out").innerHTML = userInput;
  eval(userInput);
}

function runCommand(cmd) {
  child_process.exec(cmd);
}

function loadRemote() {
  fetch("http://example.invalid/config");
  console.log("authorization=" + apiKey);
}

function queryUsers(name) {
  return "SELECT * FROM users WHERE name=" + name;
}

function handler(req) {
  const data = JSON.parse(req.body);
  localStorage.setItem("token", data.token);
  render(data.html);
}
