// Compiles KsgAnchors.sol with solc-js in standard JSON, the settings fixed
// here so the bytecode is reproducible: scripts/build_contract.sh.
const solc = require('solc'); const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const input = {language:'Solidity', sources:{'KsgAnchors.sol':{content:src}},
  settings:{optimizer:{enabled:true, runs:200}, evmVersion:'cancun', metadata:{bytecodeHash:'none'},
  outputSelection:{'*':{'*':['evm.bytecode.object','evm.deployedBytecode.object','abi','evm.methodIdentifiers']}}}};
const out = JSON.parse(solc.compile(JSON.stringify(input)));
if (out.errors) { for (const e of out.errors) console.error(e.formattedMessage); if (out.errors.some(e=>e.severity==='error')) process.exit(1); }
const c = out.contracts['KsgAnchors.sol'].KsgAnchors;
console.log(JSON.stringify({solc: solc.version(), bytecode: c.evm.bytecode.object, methods: c.evm.methodIdentifiers, abi: c.abi}));
