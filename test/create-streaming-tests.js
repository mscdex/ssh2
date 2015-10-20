'use strict'

// (c) 2015 Michael Keller, minesworld-technologies.com , published under MIT license

var basics = [
  'Exec( O:sODV,E:sODV )<->( O:wGD,E:wGD )',
  'Exec( O:sODV,E:sODV )<->( O:wGDWonDrain,E:wGDWonDrain )'
];


var settings = {
  strictStreams2: false,
  wGD: {
    maxNumber:1000,
    step:100
  },
  wGDWonDrain: {
    maxNumber:1000000,
    step:100000
  }
}


for (var i = settings.wGD.step; i <= settings.wGD.maxNumber; i += settings.wGD.step) {
  
  var options = [];
  
  if (settings.strictStreams2) {
    options.push('strictStreams2');
  }

  options.push('maxNumber=' + i);
  
  var optionsStr = ((0 < options.length) && options.join(' ') + ' ') || '';
  
  console.log(optionsStr + 'Exec( O:sODV )<->( O:wGD )');
  console.log(optionsStr + 'Exec( E:sODV )<->( E:wGD )');
  console.log(optionsStr + 'Exec( O:sODV,E:sODV )<->( O:wGD,E:wGD )');
}

for (var i = settings.wGDWonDrain.step; i <= settings.wGDWonDrain.maxNumber; i += settings.wGDWonDrain.step) {
  
  var options = [];
  
  if (settings.strictStreams2) {
    options.push('strictStreams2');
  }

  options.push('maxNumber=' + i);
  
  var optionsStr = ((0 < options.length) && options.join(' ') + ' ') || '';
  
  console.log(optionsStr + 'Exec( O:sODV )<->( O:wGDWonDrain )');
  console.log(optionsStr + 'Exec( E:sODV )<->( E:wGDWonDrain )');
  console.log(optionsStr + 'Exec( O:sODV,E:sODV )<->( O:wGDWonDrain,E:wGDWonDrain )');
}




