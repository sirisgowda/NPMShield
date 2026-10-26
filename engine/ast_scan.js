// NPMShield AST helper. Reads file paths from stdin (one per line),
// parses each with acorn and prints a JSON array. Never executes the files.
const fs = require('fs');
const acorn = require('acorn');
const walk = require('acorn-walk');

const files = fs.readFileSync(0, 'utf8').split('\n').filter(Boolean);
console.log(JSON.stringify(files.map(scan)));

function parse(src) {
  const base = { ecmaVersion: 'latest', allowReturnOutsideFunction: true, allowHashBang: true };
  try { return acorn.parse(src, { ...base, sourceType: 'script' }); }
  catch (e1) { return acorn.parse(src, { ...base, sourceType: 'module' }); }
}

function scan(file) {
  const out = { file, parsed: true, requires: [], calls: [], strings: [] };
  let src;
  try { src = fs.readFileSync(file, 'utf8'); } catch (e) { out.parsed = false; out.error = String(e); return out; }
  let ast;
  try { ast = parse(src); } catch (e) { out.parsed = false; out.error = e.message; return out; }
  walk.full(ast, (node) => {
    if (node.type === 'CallExpression') {
      const c = node.callee;
      if (c.type === 'Identifier') {
        if (c.name === 'require' && node.arguments[0] && node.arguments[0].type === 'Literal') {
          out.requires.push(String(node.arguments[0].value));
        } else {
          out.calls.push(c.name);
        }
      } else if (c.type === 'MemberExpression' && c.property.type === 'Identifier') {
        out.calls.push(c.property.name);
      }
    } else if (node.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === 'Function') {
      out.calls.push('new Function');
    } else if (node.type === 'ImportDeclaration') {
      out.requires.push(String(node.source.value));
    } else if (node.type === 'MemberExpression' && node.object.type === 'Identifier' &&
               node.object.name === 'process' && node.property.type === 'Identifier' &&
               node.property.name === 'env') {
      out.calls.push('process.env');
    } else if (node.type === 'Literal' && typeof node.value === 'string' && node.value.length >= 16) {
      if (out.strings.length < 300) out.strings.push(node.value.slice(0, 600));
    } else if (node.type === 'TemplateElement' && node.value.cooked && node.value.cooked.length >= 16) {
      if (out.strings.length < 300) out.strings.push(node.value.cooked.slice(0, 600));
    }
  });
  out.calls = Array.from(new Set(out.calls));
  out.requires = Array.from(new Set(out.requires));
  return out;
}
