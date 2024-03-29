window.onload = function() {
$userNavigation = document.getElementById('userNavigation');
$userNavigation.innerHTML = $userNavigation.innerHTML + ' \
<li class="menuDivider"></li> \
<li role="menuitem"><a class="navSubmenu" href="#" onclick="return MathToggle(this)" role="button">Stop LaTeX rendering</a></li>';

head = document.getElementsByTagName("head")[0];
script = document.createElement("script");
script.type = "text/x-mathjax-config";
script.text = ' \
  MathJax.Hub.Config({ \n \
    tex2jax: { \n \
      inlineMath: [["$ ", " $"]], \n \
      displayMath: [["$$ ", " $$"]] \n \
    }, \n \
    jax: ["input/TeX", "output/SVG"], \n \
    showMathMenu: false \n \
  }); \n \
 \n \
  MathJax.Hub.setRenderer("SVG") \n \
 \n \
  var MathQueue = null \n \
 \n \
  var MathEnable = function() { \n \
    MathQueue = setInterval(function() { \n \
      var _userContent, _wbr, _all_span, _span; \n \
      // wbr remove \n \
      _userContent = document.getElementsByClassName("userContent") \n \
      for (var i = 0, ii = _userContent.length; i < ii; i++) { \n \
        _wbr = _userContent[i].getElementsByTagName("wbr") \n \
        for (var j = 0, jj = _wbr.length; j < jj; j++) { \n \
          _wbr[j].remove() \n \
        } \n \
      } \n \
 \n \
      // span.word_break remove \n \
      _userContent = document.getElementsByClassName("userContent") \n \
      for (var i = 0, ii = _userContent.length; i < ii; i++) { \n \
        _wbr = _userContent[i].getElementsByClassName("word_break") \n \
        for (var j = 0, jj = _wbr.length; j < jj; j++) { \n \
          _wbr[j].remove() \n \
        } \n \
      } \n \
 \n \
      // span tag unwrap \n \
      _userContent = document.getElementsByClassName("userContent") \n \
      for (var i = 0, ii = _userContent.length; i < ii; i++) { \n \
        _all_span = _userContent[i].getElementsByTagName("span") \n \
        _span = [] \n \
        for (var j = 0, jj = _all_span.length; j < jj; j++) { \n \
          if (! _all_span[j].getAttribute("class")) \n \
            _span.push(_all_span[j]) \n \
        } \n \
 \n \
        while (_span.length) { \n \
          var _parent = _span[0].parentNode \n \
          if (_span[0].firstChild) { \n \
            _parent.insertBefore(_span[0].firstChild, _span[0]) \n \
          } \n \
          if (_parent) { \n \
            _parent.removeChild(_span[0]) \n \
          } else { break } \n \
        } \n \
      } \n \
 \n \
      MathJax.Hub.Queue(["setRenderer", MathJax.Hub, "SVG"]) \n \
      MathJax.Hub.Queue(["Typeset", MathJax.Hub]) \n \
    }, 2000) \n \
  } \n \
 \n \
  var MathRevert = function() { \n \
    var HTML = MathJax.HTML \n \
      , jax = MathJax.Hub.getAllJax() \n \
 \n \
    for (var i = 0, ii = jax.length; i < ii; i++) { \n \
      var script = jax[i].SourceElement() \n \
        , tex = jax[i].originalText \n \
 \n \
      if (script.type.match(/display/)) \n \
        tex = "$$ "+ tex +" $$" \n \
      else \n \
        tex = "$ "+ tex +" $" \n \
 \n \
      jax[i].Remove() \n \
 \n \
      var preview = script.previousSibling \n \
      if (preview && preview.className === "MathJax_Preview") \n \
        preview.parentNode.removeChild(preview) \n \
 \n \
      preview = HTML.Element("span", {className: "MathJax_Preview"}, [tex]) \n \
      script.parentNode.insertBefore(preview,script) \n \
    } \n \
 \n \
    window.clearInterval(MathQueue) \n \
    MathJax.Hub.queue.pending = 1 \n \
  } \n \
 \n \
  var MathText = "" \n \
  var MathToggle = function(el) { \n \
    console.log(el.innerHTML) \n \
    console.log(el.innerHTML == "Stop LaTeX rendering") \n \
    MathText = "" \n \
 \n \
    if (el.innerHTML == "Stop LaTeX rendering") { \n \
      el.innerHTML = "Running..." \n \
      MathText = "Start LaTeX rendering" \n \
      MathRevert() \n \
 \n \
      setTimeout(function() { el.innerHTML = MathText }, 1000) \n \
      return false \n \
    } \n \
    if (el.innerHTML == "Start LaTeX rendering") { \n \
      el.innerHTML = "Running..." \n \
      MathText = "Stop LaTeX rendering" \n \
      MathEnable() \n \
 \n \
      setTimeout(function() { el.innerHTML = MathText }, 2000) \n \
      return false \n \
    } \n \
    return false \n \
  } \n \
 \n \
  MathEnable() \n \
'

head.appendChild(script);
script = document.createElement("script");
script.type = "text/javascript";
script.src = "//cdn.mathjax.org/mathjax/latest/unpacked/MathJax.js?config=TeX-AMS-MML_SVG";
head.appendChild(script);
console.log("Added scripts");
}
