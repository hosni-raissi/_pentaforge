// https://gist.github.com/treyhuffine/2ced8b8c503e5246e2fd258ddbd21b8c
const debounce = (func, wait) => {
 let timeout;
 return function executedFunction(...args) {
  const later = () => {
   clearTimeout(timeout);
   func(...args);
  };
  clearTimeout(timeout);
  timeout = setTimeout(later, wait);
 };
};
function do_menu(e) {
 document.getElementById('menu').classList.toggle('open');
 e.preventDefault();
}
function reg(e) {
 document.getElementById('menu-open').addEventListener('click', do_menu);
 document.getElementById('menu-close').addEventListener('click', do_menu);
 // Hide global nav for current site
 let gn = document.getElementById('nst-gnav');
 Array.prototype.forEach.call(gn.getElementsByTagName('a'), (a)=>{
   if(document.location.hostname === a.hostname){
    a.style.display='none';
   }
  });
 gn.style.height = 'auto';
 gn.style.visibility = 'visible';
 let sn = document.getElementById('nst-sitenav');
 if (sn) {
  const mql_narrow = window.matchMedia('(max-width: 450px)');
  function move_nav(mql) {
   if (mql.matches){
    document.getElementById('nst-head').appendChild(sn);
    sn.style.margin='0px';
    sn.style.display='flex';
    return true;
   }
   return false;
  }
  if (!move_nav(mql_narrow)) {
   mql_narrow.addEventListener('change', move_nav, {once:true});
  }
  let kids = sn.getElementsByTagName('a');
  let lastkid;
  Array.prototype.forEach.call(kids, (a) => {
    if (document.location.href === a.href) {
      // Mark current page
     a.classList.add('here');
    }
    lastkid=a;
   });
  let kstyle = document.createElement('style');
  document.head.appendChild(kstyle);
  let ksheet = kstyle.sheet;
  let kfunc = function() {
    if (ksheet.cssRules.length > 0) {
     ksheet.deleteRule(0);
    }
    if (lastkid.offsetTop > sn.offsetTop) {
     let nrows = Math.floor((lastkid.offsetTop - sn.offsetTop) / lastkid.offsetHeight) + 1;
     ksheet.insertRule('#nst-sitenav > a { flex-basis: '+ Math.floor(nrows * 100 / (kids.length + 1)) +'%; }', 0);
    }
   };
  kfunc();
  var do_resize = debounce(kfunc, 250);
  window.addEventListener('resize', do_resize);
 } 
}

if (document.readyState !== "loading") {
 reg();
}
else {
 document.addEventListener('DOMContentLoaded', reg);
}
