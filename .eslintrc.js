'use strict';

/* eslint-env node */

const Module = require('module');
const path = require('path');

const ModuleFindPath = Module._findPath;
const hacks = [
  'eslint-plugin-mscdex',
];
const eslintRulesPath =
  path.join(path.dirname(process.mainModule.filename), '..', 'lib', 'rules');
Module._findPath = (request, paths, isMain) => {
  const r = ModuleFindPath(request, paths.concat(eslintRulesPath), isMain);
  if (!r) {
    if (hacks.includes(request))
      return path.join(__dirname, '.eslint-plugins', request);
  }
  return r;
};

module.exports = {
  root: true,
  env: { node: true, es6: true },
  plugins: ['mscdex'],
  parserOptions: { sourceType: 'script', ecmaVersion: '2020' },
  rules: {
    // ESLint built-in rules
    // https://eslint.org/docs/rules/
    'accessor-pairs': 'error',
    'array-callback-return': 'error',
    'arrow-parens': ['error', 'always'],
    'arrow-spacing': ['error', { before: true, after: true }],
    'block-scoped-var': 'error',
    'block-spacing': 'error',
    'brace-style': ['error', '1tbs', { allowSingleLine: true }],
    'capitalized-comments': ['error', 'always', {
      line: {
        // Ignore all lines that have less characters than 20 and all lines that
        // start with something that looks like a variable name or code.
        // eslint-disable-next-line max-len
        ignorePattern: '.{0,20}$|[a-z]+ ?[0-9A-Z_.(/=:[#-]|std|http|ssh|ftp|(let|var|const) [a-z_A-Z0-9]+ =|[b-z] |[a-z]*[0-9].* ',
        ignoreInlineComments: true,
        ignoreConsecutiveComments: true,
      },
      block: {
        ignorePattern: '.*',
      },
    }],
    'comma-dangle': ['error', 'only-multiline'],
    'comma-spacing': 'error',
    'comma-style': 'error',
    'computed-property-spacing': 'error',
    'constructor-super': 'error',
    'default-case-last': 'error',
    'dot-location': ['error', 'property'],
    'dot-notation': 'error',
    'eol-last': 'error',
    'eqeqeq': ['error', 'smart'],
    'for-direction': 'error',
    'func-call-spacing': 'error',
    'func-name-matching': 'error',
    'func-style': ['error', 'declaration', { allowArrowFunctions: true }],
    'getter-return': 'error',
    'key-spacing': ['error', { mode: 'strict' }],
    'keyword-spacing': 'error',
    'linebreak-style': ['error', 'unix'],
    'max-len': ['error', {
      code: 80,
      ignorePattern: '^// Flags:',
      ignoreRegExpLiterals: true,
      ignoreUrls: true,
      tabWidth: 2,
    }],
    'new-parens': 'error',
    'no-async-promise-executor': 'error',
    'no-class-assign': 'error',
    'no-confusing-arrow': 'error',
    'no-const-assign': 'error',
    'no-constructor-return': 'error',
    'no-control-regex': 'error',
    'no-debugger': 'error',
    'no-delete-var': 'error',
    'no-dupe-args': 'error',
    'no-dupe-class-members': 'error',
    'no-dupe-keys': 'error',
    'no-dupe-else-if': 'error',
    'no-duplicate-case': 'error',
    'no-duplicate-imports': 'error',
    'no-else-return': ['error', { allowElseIf: true }],
    'no-empty-character-class': 'error',
    'no-ex-assign': 'error',
    'no-extra-boolean-cast': 'error',
    'no-extra-parens': ['error', 'functions'],
    'no-extra-semi': 'error',
    'no-fallthrough': 'error',
    'no-func-assign': 'error',
    'no-global-assign': 'error',
    'no-invalid-regexp': 'error',
    'no-irregular-whitespace': 'error',
    'no-lonely-if': 'error',
    'no-misleading-character-class': 'error',
    'no-mixed-requires': 'error',
    'no-mixed-spaces-and-tabs': 'error',
    'no-multi-spaces': ['error', { ignoreEOLComments: true }],
    'no-multiple-empty-lines': ['error', { max: 2, maxEOF: 0, maxBOF: 0 }],
    'no-new-require': 'error',
    'no-new-symbol': 'error',
    'no-obj-calls': 'error',
    'no-octal': 'error',
    'no-path-concat': 'error',
    'no-proto': 'error',
    'no-redeclare': 'error',
    /* eslint-disable max-len */
    'no-restricted-syntax': [
      'error',
      {
        selector: "CallExpression[callee.name='setTimeout'][arguments.length<2]",
        message: '`setTimeout()` must be invoked with at least two arguments.',
      },
      {
        selector: "CallExpression[callee.name='setInterval'][arguments.length<2]",
        message: '`setInterval()` must be invoked with at least two arguments.',
      },
      {
        selector: 'ThrowStatement > CallExpression[callee.name=/Error$/]',
        message: 'Use `new` keyword when throwing an `Error`.',
      }
    ],
    /* eslint-enable max-len */
    'no-return-await': 'error',
    'no-self-assign': 'error',
    'no-self-compare': 'error',
    'no-setter-return': 'error',
    'no-shadow-restricted-names': 'error',
    'no-tabs': 'error',
    'no-template-curly-in-string': 'error',
    'no-this-before-super': 'error',
    'no-throw-literal': 'error',
    'no-trailing-spaces': 'error',
    'no-undef': ['error', { typeof: true }],
    'no-undef-init': 'error',
    'no-unexpected-multiline': 'error',
    'no-unreachable': 'error',
    'no-unsafe-finally': 'error',
    'no-unsafe-negation': 'error',
    'no-unused-expressions': ['error', { allowShortCircuit: true }],
    'no-unused-labels': 'error',
    'no-unused-vars': ['error', { args: 'none', caughtErrors: 'all' }],
    'no-use-before-define': ['error', {
      classes: true,
      functions: false,
      variables: false,
    }],
    'no-useless-backreference': 'error',
    'no-useless-call': 'error',
    'no-useless-catch': 'error',
    'no-useless-concat': 'error',
    'no-useless-constructor': 'error',
    'no-useless-escape': 'error',
    'no-useless-return': 'error',
    'no-var': 'error',
    'no-void': 'error',
    'no-whitespace-before-property': 'error',
    'no-with': 'error',
    'object-curly-spacing': ['error', 'always'],
    'one-var': ['error', { initialized: 'never' }],
    'one-var-declaration-per-line': 'error',
    'operator-linebreak': ['error', 'before', { overrides: { '=': 'after' } }],
    'padding-line-between-statements': [
      'error',
      { blankLine: 'always', prev: 'function', next: 'function' },
    ],
    'prefer-const': ['error', { ignoreReadBeforeAssign: true }],
    'quote-props': ['error', 'consistent'],
    'rest-spread-spacing': 'error',
    'semi': 'error',
    'semi-spacing': 'error',
    'space-before-blocks': ['error', 'always'],
    'space-before-function-paren': ['error', {
      anonymous: 'never',
      named: 'never',
      asyncArrow: 'always',
    }],
    'space-in-parens': ['error', 'never'],
    'space-infix-ops': 'error',
    'space-unary-ops': 'error',
    'spaced-comment': ['error', 'always', {
      'block': { 'balanced': true },
      'exceptions': ['-'],
    }],
    'strict': ['error', 'global'],
    'symbol-description': 'error',
    'template-curly-spacing': 'error',
    'unicode-bom': 'error',
    'use-isnan': 'error',
    'valid-typeof': 'error',

    // Custom rules
    'mscdex/curly': ['error', 'multi-or-nest', 'consistent'],
    'mscdex/quotes': ['error', 'single', { avoidEscape: true }],
  },
  globals: {
    Atomics: 'readable',
    BigInt: 'readable',
    BigInt64Array: 'readable',
    BigUint64Array: 'readable',
    TextEncoder: 'readable',
    TextDecoder: 'readable',
    globalThis: 'readable',
  },
};
