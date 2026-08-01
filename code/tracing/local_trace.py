import argparse
import http.server
import json
import logging
import os
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

import zstandard as zstd
from tqdm import tqdm

SCRIPT_DIR = Path(__file__).resolve().parent
CDPSCAN = SCRIPT_DIR / "implementataion" / "compweb" / "scan" / "scan-node" / "cdpscan.py"
CDPSCAN_CWD = CDPSCAN.parent  # cdpscan.py must run from here so mutation_observers/ is found

_CHROME_CANDIDATES = [
    "google-chrome-stable",
    "google-chrome",
    "chromium-browser",
    "chromium",
]

_JQUERY_PATH = CDPSCAN_CWD / "jquery.min.js"

def _load_jquery() -> bytes:
    """Load jQuery bytes at call time, not module-import time.
    This avoids a race where the tracer starts before jquery.min.js exists."""
    if _JQUERY_PATH.exists():
        data = _JQUERY_PATH.read_bytes()
        if data:
            return data
    log.warning("jquery.min.js not found or empty at %s — scripts using jQuery will fail", _JQUERY_PATH)
    return b""

_WP_STUBS = """
window.wp = window.wp || {};
window.wp.hooks = window.wp.hooks || {addAction:function(){},addFilter:function(){},applyFilters:function(n,v){return v;},doAction:function(){}};
window.wp.element = window.wp.element || {createElement:function(){return null;},render:function(){},Fragment:'fragment'};
window.wp.i18n = window.wp.i18n || {__:function(s){return s;},_x:function(s){return s;},sprintf:function(s){return s;}};
window.wp.apiFetch = window.wp.apiFetch || function(opts){return Promise.resolve({});};
window.wp.data = window.wp.data || {select:function(){return {};},dispatch:function(){return {};},subscribe:function(){return function(){};},useSelect:function(){},useDispatch:function(){}};
window.wp.blocks = window.wp.blocks || {registerBlockType:function(){},getBlockType:function(){return null;}};
window.wp.domReady = window.wp.domReady || function(fn){if(document.readyState!=='loading'){fn();}else{document.addEventListener('DOMContentLoaded',fn);}};
window.wp.compose = window.wp.compose || {compose:function(fn){return fn;},withState:function(){return function(C){return C;};}};
window.ajaxurl = window.ajaxurl || '/wp-admin/admin-ajax.php';
window.wpApiSettings = window.wpApiSettings || {root:'/wp-json/',nonce:'testnonce123'};
window.woocommerce_params = window.woocommerce_params || {ajax_url:'/wp-admin/admin-ajax.php',wc_ajax_url:'/?wc-ajax=%endpoint%'};
window.wc_cart_fragments_params = window.wc_cart_fragments_params || {ajax_url:'/wp-admin/admin-ajax.php',wc_ajax_url:'/?wc-ajax=%endpoint%',cart_hash_key:'woocommerce_cart_hash',fragment_name:'wc_fragments',request_timeout:'5000'};
window.wc_add_to_cart_params = window.wc_add_to_cart_params || {ajax_url:'/wp-admin/admin-ajax.php',wc_ajax_url:'/?wc-ajax=%endpoint%',i18n_view_cart:'View cart',cart_url:'/cart/'};
window.wc = window.wc || {blocksRegistry:{registerCheckoutFilters:function(){},registerCheckoutBlock:function(){}}};
window._wpnonce = window._wpnonce || 'testnonce123';
window.wp_localize_data = window.wp_localize_data || {};
window.pagenow = window.pagenow || 'front';
window.current_user_id = window.current_user_id || 0;
window.is_user_logged_in = window.is_user_logged_in || false;
window.dataLayer = window.dataLayer || [];
window.gtag = window.gtag || function(){window.dataLayer.push(arguments);};
window._gaq = window._gaq || [];
window.ga = window.ga || function(){(window.ga.q=window.ga.q||[]).push(arguments);};
window.fbq = window.fbq || function(){(window.fbq.q=window.fbq.q||[]).push(arguments);};window._fbq=window.fbq;
window.Cookiebot = window.Cookiebot || {consent:{marketing:false,statistics:false,preferences:false},runScripts:function(){}};
window.addthis = window.addthis || {layers:function(){},options:{},addEventListener:function(){},event:{}};
window.WPCOM_sharing_counts = window.WPCOM_sharing_counts || {};
// Full jQuery stub with .fn, .ajax, .extend so plugin scripts don't bail on TypeError.
if (!window.jQuery || typeof window.jQuery.fn === 'undefined') {
    (function(){
        var $j = function(sel, ctx){ return new $j.fn.init(sel, ctx); };
        $j.fn = $j.prototype = {
            jquery:'3.7.1', constructor:$j,
            init:function(sel){ return this; },
            extend:function(o){ for(var k in o){ this[k]=o[k]; } return this; },
            on:function(){ return this; }, off:function(){ return this; },
            ready:function(fn){ try{ fn($j); }catch(e){} return this; },
            each:function(fn){ return this; }, map:function(){ return this; },
            find:function(){ return this; }, filter:function(){ return this; },
            children:function(){ return this; }, parent:function(){ return this; },
            closest:function(){ return this; }, siblings:function(){ return this; },
            first:function(){ return this; }, last:function(){ return this; },
            eq:function(){ return this; }, not:function(){ return this; },
            add:function(){ return this; }, addBack:function(){ return this; },
            append:function(){ return this; }, prepend:function(){ return this; },
            before:function(){ return this; }, after:function(){ return this; },
            html:function(v){ return v===undefined?'':this; },
            text:function(v){ return v===undefined?'':this; },
            val:function(v){ return v===undefined?'':this; },
            attr:function(k,v){ return v===undefined?null:this; },
            prop:function(k,v){ return v===undefined?false:this; },
            data:function(k,v){ return v===undefined?undefined:this; },
            css:function(){ return this; }, addClass:function(){ return this; },
            removeClass:function(){ return this; }, toggleClass:function(){ return this; },
            hasClass:function(){ return false; },
            show:function(){ return this; }, hide:function(){ return this; },
            toggle:function(){ return this; }, is:function(){ return false; },
            index:function(){ return -1; }, length:0, get:function(){ return undefined; },
            trigger:function(){ return this; }, triggerHandler:function(){ return this; },
            click:function(fn){ return fn?this.on('click',fn):this; },
            submit:function(fn){ return fn?this.on('submit',fn):this; },
            focus:function(fn){ return fn?this.on('focus',fn):this; },
            blur:function(fn){ return fn?this.on('blur',fn):this; },
            change:function(fn){ return fn?this.on('change',fn):this; },
            keyup:function(fn){ return fn?this.on('keyup',fn):this; },
            keydown:function(fn){ return fn?this.on('keydown',fn):this; },
            mouseenter:function(fn){ return fn?this.on('mouseenter',fn):this; },
            mouseleave:function(fn){ return fn?this.on('mouseleave',fn):this; },
            hover:function(a,b){ return this; }, bind:function(){ return this; },
            unbind:function(){ return this; }, delegate:function(){ return this; },
            undelegate:function(){ return this; }, live:function(){ return this; },
            die:function(){ return this; }, one:function(){ return this; },
            serialize:function(){ return ''; }, serializeArray:function(){ return []; },
            width:function(){ return 0; }, height:function(){ return 0; },
            offset:function(){ return {top:0,left:0}; },
            position:function(){ return {top:0,left:0}; },
            scrollTop:function(v){ return v===undefined?0:this; },
            scrollLeft:function(v){ return v===undefined?0:this; },
            animate:function(p,d,e,cb){ if(typeof d==='function')d(); if(typeof e==='function')e(); if(typeof cb==='function')cb(); return this; },
            fadeIn:function(d,cb){ if(typeof d==='function')d(); if(typeof cb==='function')cb(); return this; },
            fadeOut:function(d,cb){ if(typeof d==='function')d(); if(typeof cb==='function')cb(); return this; },
            slideDown:function(d,cb){ if(typeof d==='function')d(); if(typeof cb==='function')cb(); return this; },
            slideUp:function(d,cb){ if(typeof d==='function')d(); if(typeof cb==='function')cb(); return this; },
            slideToggle:function(d,cb){ if(typeof d==='function')d(); if(typeof cb==='function')cb(); return this; },
            stop:function(){ return this; }, delay:function(){ return this; },
            dequeue:function(){ return this; }, queue:function(){ return this; },
            promise:function(){ return {done:function(){return this;},then:function(){return this;}}; },
            toArray:function(){ return []; }, pushStack:function(){ return this; },
            end:function(){ return this; },
        };
        $j.fn.init.prototype = $j.fn;
        $j.extend = $j.fn.extend = function(o){ for(var k in o){ this[k]=o[k]; } return this; };
        $j.each = function(o, fn){ if(Array.isArray(o)){o.forEach(function(v,i){fn.call(v,i,v);});}else{for(var k in o)fn.call(o[k],k,o[k]);} return $j; };
        $j.map = function(o, fn){ return (Array.isArray(o)?o:Object.values(o)).map(fn); };
        $j.grep = function(arr,fn){ return arr.filter(fn); };
        $j.merge = function(a,b){ return a.concat(Array.prototype.slice.call(b)); };
        $j.inArray = function(v,arr){ return arr.indexOf(v); };
        $j.isArray = Array.isArray;
        $j.isFunction = function(v){ return typeof v==='function'; };
        $j.isPlainObject = function(v){ return v!==null&&typeof v==='object'&&Object.getPrototypeOf(v)===Object.prototype; };
        $j.isEmptyObject = function(v){ return Object.keys(v).length===0; };
        $j.type = function(v){ return v===null?'null':typeof v; };
        $j.noop = function(){};
        $j.now = Date.now;
        $j.trim = function(s){ return (s||'').trim(); };
        $j.proxy = function(fn,ctx){ return fn.bind(ctx); };
        $j.parseJSON = JSON.parse.bind(JSON);
        $j.parseHTML = function(){ return []; };
        $j.parseXML = function(){ return null; };
        $j.globalEval = function(code){ try{(0,eval)(code);}catch(e){} };
        $j.contains = function(a,b){ return a!==b&&a.contains(b); };
        $j.ajax = function(url, opts){
            if(typeof url==='object'){opts=url;url=opts.url;}
            opts=opts||{};
            var d={done:function(cb){if(cb)try{cb({});}catch(e){}return d;},fail:function(cb){return d;},always:function(cb){if(cb)try{cb();}catch(e){}return d;},then:function(cb){if(cb)try{cb({});}catch(e){}return d;},abort:function(){return d;}};
            if(opts.success)try{opts.success({});}catch(e){}
            return d;
        };
        $j.get = $j.post = $j.getJSON = $j.getScript = function(url, data, cb){
            if(typeof data==='function'){cb=data;}
            var d={done:function(fn){if(fn)try{fn({});}catch(e){}return d;},fail:function(){return d;},always:function(fn){if(fn)try{fn();}catch(e){}return d;}};
            if(typeof cb==='function')try{cb({});}catch(e){}
            return d;
        };
        $j.Deferred = function(fn){
            var d={resolve:function(){d._done.forEach(function(f){try{f();}catch(e){}});return d;},reject:function(){d._fail.forEach(function(f){try{f();}catch(e){}});return d;},notify:function(){return d;},_done:[],_fail:[],_prog:[],done:function(f){d._done.push(f);return d;},fail:function(f){d._fail.push(f);return d;},progress:function(f){d._prog.push(f);return d;},always:function(f){d._done.push(f);d._fail.push(f);return d;},then:function(f){d._done.push(f);return d;},promise:function(){return d;},state:function(){return 'pending';}};
            if(typeof fn==='function')try{fn(d.resolve,d.reject);}catch(e){}
            return d;
        };
        $j.when = function(){ var d=$j.Deferred(); d.resolve(); return d; };
        $j.Event = function(type,props){ var e={type:type,preventDefault:function(){},stopPropagation:function(){},stopImmediatePropagation:function(){},isDefaultPrevented:function(){return false;},isPropagationStopped:function(){return false;},originalEvent:null}; if(props)Object.assign(e,props); return e; };
        $j.error = function(msg){ throw new Error(msg); };
        $j.cssHooks = {}; $j.cssNumber = {}; $j.expr = {filters:{},pseudos:{},':':{}};
        $j.event = {add:function(){},remove:function(){},trigger:function(){},dispatch:function(){},handlers:function(){}};
        $j.valHooks = {}; $j.propFix = {}; $j.attrHooks = {};
        $j.fx = {off:true,speeds:{slow:600,fast:200,_default:400}};
        $j.support = {ajax:true,cors:true,boxSizing:true};
        $j.noConflict = function(){ return $j; };
        window.jQuery = window.$ = $j;
    }());
}

/* ── Theme globals ────────────────────────────────────────────────────── */
window.astra = window.astra || {break_point:921};
window.astraAddon = window.astraAddon || {responsive_breakpoints:{desktop:'9999',tablet:'768',mobile:'544'}};
window.AstraToggleSetup = window.AstraToggleSetup || {};
window.AstraToggleSetup.menu = window.AstraToggleSetup.menu || [];
window.astra_addon_js = window.astra_addon_js || {break_point:921};

window.oceanwpLocalize = window.oceanwpLocalize || {
    nonce:'testnonce',isRTL:'0',
    menuSearchStyle:'disabled',
    sidrSource:'#site-navigation, .oceanwp-mobile-menu',
    sidrDisplace:'1',sidrSide:'left',
    mobileMenuControl:'.mobile-menu-toggle',
    sidrDropdownTarget:'button',
    verticalHeaderTarget:'#site-header',
    customSelects:'.woocommerce-ordering .orderby, #dropdown_product_cat'
};

window.kadenceConfig = window.kadenceConfig || {screenReader:{expand:'Expand',expandOf:'Expand child menu of',collapse:'Collapse',collapseOf:'Collapse child menu of'},breakPoints:{desktop:'1024',tablet:'768'},scrollOffset:'0'};
window.kadence_screenreader_text = window.kadence_screenreader_text || {expand:'Expand child menu',collapse:'Collapse child menu'};

window.generatepressMenu = window.generatepressMenu || {toggleOpenedSubMenus:'1',openSubMenuLabel:'Open sub-menu',closeSubMenuLabel:'Close sub-menu'};

window.flatsome_vars = window.flatsome_vars || {ajaxurl:'/wp-admin/admin-ajax.php',lazy_load_background:'1',quickview:'',header_sticky:'',header_transparent:''};
window.Flatsome = window.Flatsome || {};

/* ── Page builders ────────────────────────────────────────────────────── */
window.elementorModules = window.elementorModules || {
    utils:{Module:function(){}},
    editor:{utils:{}},
    frontend:{handlers:{Base:function(){this.onInit=function(){};this.bindEvents=function(){};this.getDefaultSettings=function(){return{};};}}}
};
window.elementorFrontendConfig = window.elementorFrontendConfig || {
    environmentMode:{edit:false,wpPreview:false,isScriptDebug:false},
    i18n:{},is_rtl:false,breakpoints:{xs:0,sm:480,md:768,lg:1025,xl:1440,xxl:1600},
    version:'3.18.0',urls:{assets:'/wp-content/plugins/elementor/assets/'},
    nonces:{frontend_builder_nonce:'testnonce123'},
    settings:{page:{},editorPreferences:{}},
    kit:{active_breakpoints:['viewport_mobile','viewport_tablet']}
};

window.bricksIsFrontend = window.bricksIsFrontend !== undefined ? window.bricksIsFrontend : true;
window.bricksData = window.bricksData || {nonce:'testnonce123',ajaxurl:'/wp-admin/admin-ajax.php',postId:1,isBuilder:false,version:'1.9'};

window.BreakdanceFrontend = window.BreakdanceFrontend || {init:function(){}};

/* ── Plugins ──────────────────────────────────────────────────────────── */
window.wpcf7 = window.wpcf7 || {api:{root:'/wp-json/',namespace:'contact-form-7/v1'},cached:1};
window.wpcf7_recaptcha = window.wpcf7_recaptcha || {sitekey:'6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',actions:{homepage:'homepage',contactform:'contactform'}};

window.WP_Statistics_Tracker_Object = window.WP_Statistics_Tracker_Object || {params:{request:{header:{},rest:{},params:{}},options:{}}};

window.WPD = window.WPD || {app:{},modules:{},config:{}};

/* ── JS runtime stubs ─────────────────────────────────────────────────── */
// Old-style webpack chunk loader expected by some bundled plugins.
if (!window.webpackJsonp) {
    window.webpackJsonp = [];
    window.webpackJsonp.push = function(item) {
        Array.prototype.push.call(window.webpackJsonp, item);
    };
}

// React stub (component-defining plugins that test typeof React).
window.React = window.React || {
    createElement:function(){return null;},
    Component:function(){},
    PureComponent:function(){},
    Fragment:'fragment',
    version:'18.2.0',
    createRef:function(){return {current:null};},
    forwardRef:function(fn){return fn;},
    memo:function(c){return c;}
};
window.ReactDOM = window.ReactDOM || {
    render:function(){},
    createRoot:function(){return {render:function(){},unmount:function(){}};},
    hydrate:function(){}
};

// Underscore / Lodash stub so scripts that check `typeof _` don't bail.
window._ = window._ || (function(){
    var fn = function(v){return v;};
    fn.each = fn.forEach = function(c,f){if(c){(Array.isArray(c)?c:Object.values(c)).forEach(f);}};
    fn.map = function(c,f){return (Array.isArray(c)?c:Object.values(c)).map(f);};
    fn.extend = Object.assign;
    fn.defaults = function(o){for(var i=1;i<arguments.length;i++){var s=arguments[i];for(var k in s){if(!(k in o))o[k]=s[k];}}return o;};
    fn.isFunction = function(v){return typeof v==='function';};
    fn.isObject = function(v){return v!==null&&typeof v==='object';};
    fn.isArray = Array.isArray;
    fn.noop = function(){};
    fn.noConflict = function(){return fn;};
    return fn;
}());

/* ── More plugins / libraries (from ReferenceError analysis) ────────────── */
// The Events Calendar
window.tribe = window.tribe || {events:{},tickets:{},common:{},store:{dispatch:function(){},getState:function(){return {};}}};
window.tribe_js_config = window.tribe_js_config || {ajaxurl:'/wp-admin/admin-ajax.php',rest_url:'/wp-json/tribe/events/v1/'};

// Contact Form 7 extra
window.ctPublicFunctions = window.ctPublicFunctions || function(){};

// Avada theme
window.fusion = window.fusion || {};
window.fusionJSVars = window.fusionJSVars || {ajaxurl:'/wp-admin/admin-ajax.php',breakpoints:{}};
window.fusionVideoBgVars = window.fusionVideoBgVars || {};

// Gravity Forms
window.gform = window.gform || {
    addAction:function(){},addFilter:function(n,fn,p,ctx){try{return fn;}catch(e){}},
    applyFilters:function(n,v){return v;},doAction:function(){},
    hooks:{action:{},filter:{}},utils:{isAdmin:function(){return false;}}
};
window.gf_global = window.gf_global || {gf_currency_config:{name:'US Dollar',symbol_left:'$',symbol_right:'',symbol_padding:'',thousand_separator:',',decimal_separator:'.',decimals:2},base_url:'/wp-content/plugins/gravityforms',number_formats:[]};

// GreenSock (GSAP)
window.gsap = window.gsap || {
    to:function(){return {pause:function(){},play:function(){},kill:function(){}};},
    from:function(){return {pause:function(){},play:function(){},kill:function(){}};},
    fromTo:function(){return {pause:function(){},play:function(){},kill:function(){}};},
    set:function(){}, timeline:function(){return {to:function(){return this;},from:function(){return this;},add:function(){return this;},play:function(){return this;},pause:function(){return this;},kill:function(){return this;}};},
    registerPlugin:function(){}, config:function(){}, ticker:{add:function(){},remove:function(){}},
    utils:{toArray:function(){return [];},clamp:function(mn,mx,v){return v;}}
};
window.TweenMax = window.TweenMax || window.gsap;
window.TweenLite = window.TweenLite || window.gsap;

// MediaElement.js
window.mejs = window.mejs || {
    Utils:{},MepDefaults:{},Renderers:{},players:{},
    MediaFeatures:{isiOS:false,isAndroid:false,isChrome:true}
};
window.MediaElement = window.MediaElement || function(){};
window.MediaElementPlayer = window.MediaElementPlayer || function(){};
window.mejsL10n = window.mejsL10n || {language:'en',strings:{}};

// Leaflet maps (L)
window.L = window.L || (function(){
    var noop=function(){}, chain=function(){return _L;};
    var _L = {
        map:function(){return {setView:chain,addLayer:chain,removeLayer:chain,on:chain,off:chain,fitBounds:chain,panTo:chain,getZoom:function(){return 13;},getCenter:function(){return {lat:0,lng:0};}};},
        tileLayer:function(){return {addTo:chain};},
        marker:function(){return {addTo:chain,bindPopup:chain,openPopup:chain,on:chain,setIcon:chain};},
        icon:function(){return {};},
        divIcon:function(){return {};},
        latLng:function(a,b){return {lat:a,lng:b,distanceTo:function(){return 0;}};},
        latLngBounds:function(){return {extend:chain,getCenter:function(){return {lat:0,lng:0};}};},
        polyline:function(){return {addTo:chain,on:chain};},
        polygon:function(){return {addTo:chain,on:chain};},
        circle:function(){return {addTo:chain,on:chain};},
        geoJSON:function(){return {addTo:chain};},
        featureGroup:function(){return {addTo:chain,addLayer:chain};},
        layerGroup:function(){return {addTo:chain,addLayer:chain};},
        control:{layers:function(){return {addTo:chain};},scale:function(){return {addTo:chain};}},
        DomUtil:{create:function(){return document.createElement('div');},addClass:noop,removeClass:noop},
        DomEvent:{on:noop,off:noop,stopPropagation:noop,preventDefault:noop},
        version:'1.9.4',noConflict:function(){return _L;}
    };
    return _L;
}());

// Three.js (3D viewer plugins)
window.THREE = window.THREE || {
    Scene:function(){this.add=function(){};this.children=[];},
    PerspectiveCamera:function(){this.position={set:function(){}};this.lookAt=function(){};},
    WebGLRenderer:function(){this.setSize=function(){};this.render=function(){};this.domElement=document.createElement('canvas');},
    BoxGeometry:function(){},SphereGeometry:function(){},PlaneGeometry:function(){},
    MeshBasicMaterial:function(){},MeshLambertMaterial:function(){},MeshPhongMaterial:function(){},
    Mesh:function(){this.position={set:function(){}};this.rotation={set:function(){}};},
    Vector3:function(x,y,z){this.x=x||0;this.y=y||0;this.z=z||0;this.set=function(a,b,c){this.x=a;this.y=b;this.z=c;return this;};},
    Color:function(){},TextureLoader:function(){this.load=function(){};},
    AmbientLight:function(){},DirectionalLight:function(){},
    Clock:function(){this.getDelta=function(){return 0.016;};},
    AnimationMixer:function(){this.update=function(){};this.clipAction=function(){return {play:function(){return this;},setLoop:function(){return this;}};};},
    REVISION:'150'
};
window.THREE3DP = window.THREE3DP || {};
"""

_DOM_BODY = (
    '<header id="masthead" class="site-header">'
    '<nav id="site-navigation" class="main-navigation" role="navigation">'
    '<ul id="menu-primary" class="menu nav-menu">'
    '<li class="menu-item menu-item-1"><a href="/">Home</a></li>'
    '<li class="menu-item menu-item-2"><a href="/about/">About</a></li>'
    '<li class="menu-item menu-item-3 menu-item-has-children"><a href="/shop/">Shop</a>'
    '<ul class="sub-menu"><li><a href="/shop/category/">Category</a></li></ul></li>'
    '<li class="menu-item menu-item-4"><a href="/contact/">Contact</a></li>'
    '</ul></nav></header>'
    '<div id="page" class="site">'
    '<main id="main" class="site-main" role="main">'
    '<article id="post-1" class="post-1 post type-post status-publish">'
    '<header class="entry-header">'
    '<h1 class="entry-title">Sample Page</h1>'
    '</header>'
    '<div class="entry-content wp-block-post-content">'
    '<p>Sample page content paragraph one.</p>'
    '<p>Another paragraph with <a href="/page/">a link</a> and <strong>bold text</strong>.</p>'
    '<div class="wp-block-buttons">'
    '<div class="wp-block-button">'
    '<a class="wp-block-button__link wp-element-button" href="/action/">Click Button</a>'
    '</div></div>'
    '<div class="woocommerce">'
    '<form class="cart" method="post" enctype="multipart/form-data">'
    '<input type="hidden" name="add-to-cart" value="1">'
    '<button type="submit" class="button single_add_to_cart_button alt" data-product-id="1">Add to cart</button>'
    '</form>'
    '<div class="woocommerce-notices-wrapper"></div>'
    '</div>'
    '</div>'
    '</article>'
    '<div id="respond" class="comment-respond">'
    '<form id="commentform" class="comment-form" method="post" action="/wp-comments-post.php">'
    '<p class="comment-form-author">'
    '<label for="author">Name <span class="required">*</span></label>'
    '<input id="author" name="author" type="text" value="" size="30" maxlength="245" autocomplete="name">'
    '</p>'
    '<p class="comment-form-email">'
    '<label for="email">Email <span class="required">*</span></label>'
    '<input id="email" name="email" type="email" value="" size="30" maxlength="100" autocomplete="email">'
    '</p>'
    '<p class="comment-form-url">'
    '<label for="url">Website</label>'
    '<input id="url" name="url" type="url" value="" size="30" maxlength="200" autocomplete="url">'
    '</p>'
    '<p class="comment-form-comment">'
    '<label for="comment">Comment <span class="required">*</span></label>'
    '<textarea id="comment" name="comment" cols="45" rows="5" maxlength="65525"></textarea>'
    '</p>'
    '<p class="form-submit">'
    '<input name="submit" type="submit" id="submit" class="submit" value="Post Comment">'
    '<input type="hidden" name="comment_post_ID" value="1">'
    '<input type="hidden" name="comment_parent" value="0">'
    '</p>'
    '</form></div>'
    '</main>'
    '<aside id="secondary" class="widget-area" role="complementary">'
    '<section class="widget widget_search">'
    '<form role="search" method="get" class="search-form" action="/">'
    '<label><span class="screen-reader-text">Search for:</span>'
    '<input type="search" class="search-field" placeholder="Search..." value="" name="s">'
    '</label>'
    '<input type="submit" class="search-submit" value="Search">'
    '</form></section>'
    '<section class="widget widget_recent_entries"><ul>'
    '<li><a href="/post-1/">Recent Post One</a></li>'
    '<li><a href="/post-2/">Recent Post Two</a></li>'
    '</ul></section>'
    '</aside>'
    '</div>'
    '<footer id="colophon" class="site-footer" role="contentinfo">'
    '<div class="site-info">'
    '<a href="/">WordPress Site</a> &mdash; Built with WordPress'
    '</div></footer>'
    '<div id="cookie-notice" class="cookie-notice-hidden" data-notice="true"></div>'
)

_HTML_TEMPLATE = (
    "<!DOCTYPE html><html lang=\"en\">"
    "<head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>WordPress Site</title></head>"
    "<body class=\"home page-template-default page\">"
    + _DOM_BODY +
    "<script src=\"/jquery.js\"></script>"
    "<script>{stubs}</script>"
    "<script src=\"/target.js\"></script>"
    "</body></html>"
).format(stubs=_WP_STUBS)

_HTML_TEMPLATE_MODULE = (
    "<!DOCTYPE html><html lang=\"en\">"
    "<head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>WordPress Site</title></head>"
    "<body class=\"home page-template-default page\">"
    + _DOM_BODY +
    "<script src=\"/jquery.js\"></script>"
    "<script>{stubs}</script>"
    "<script type=\"module\" src=\"/target.js\"></script>"
    "</body></html>"
).format(stubs=_WP_STUBS)

log = logging.getLogger(__name__)

def _find_chrome_binary(preferred: str) -> str:
    for candidate in ([preferred] + [c for c in _CHROME_CANDIDATES if c != preferred]):
        if shutil.which(candidate):
            if candidate != preferred:
                log.info("Chrome not found as '%s', using '%s'", preferred, candidate)
            return candidate
    raise RuntimeError(f"No Chrome binary found. Tried: {_CHROME_CANDIDATES}")

def _find_free_port(base: int, used: set, lock: Lock) -> int:
    with lock:
        for offset in range(500):
            port = base + offset
            if port in used:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("127.0.0.1", port))
                    used.add(port)
                    return port
                except OSError:
                    continue
    raise RuntimeError(f"No free port found near {base}")

def _release_port(port: int, used: set, lock: Lock) -> None:
    with lock:
        used.discard(port)

def _wait_chrome_ready(port: int, timeout: int = 20) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=2) as r:
                r.read()
            return True
        except Exception:
            time.sleep(0.5)
    return False

def _kill_group(pid: int) -> None:
    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except Exception:
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

def _is_es_module(js_content: str) -> bool:
    """Heuristic: does this script use ES module import/export syntax?"""
    for line in js_content.splitlines()[:30]:
        stripped = line.strip()
        if stripped.startswith(("import ", "import{", "export ", "export{")):
            return True
    return False

_EMPTY_JS: bytes = b"/* local-tracer stub */"
_EMPTY_JSON: bytes = b'{"success":false,"data":""}'

def _make_handler(js_bytes: bytes, html_bytes: bytes, jquery_bytes: bytes):
    """Return an HTTPRequestHandler class that serves js_bytes at /target.js.

    Routing rules (in order):
      /target.js            → target JS bytes
      /jquery.js            → jQuery bytes
      *.js                  → empty JS stub  (prevents parse errors from missing dependencies)
      *.json                → empty JSON     (prevents JSON.parse errors)
      /wp-admin/admin-ajax.php, /?wc-ajax=*  → {"success":false,"data":""}
      /wp-json/*            → {}             (REST API stub)
      everything else       → 404            (avoids serving HTML where JS/JSON is expected)
    """
    class _Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, status: int, ct: str, body: bytes) -> None:
            try:
                self.send_response(status)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)
            except BrokenPipeError:
                pass

        def do_GET(self):
            path = self.path.split("?")[0].split("#")[0]  # strip query/fragment
            if path == "/target.js":
                self._send(200, "application/javascript; charset=utf-8", js_bytes)
            elif path == "/jquery.js":
                self._send(200, "application/javascript; charset=utf-8", jquery_bytes)
            elif path.endswith(".js") or path.endswith(".mjs"):
                self._send(200, "application/javascript; charset=utf-8", _EMPTY_JS)
            elif path.endswith(".json"):
                self._send(200, "application/json", _EMPTY_JSON)
            elif path in ("/wp-admin/admin-ajax.php",) or "wc-ajax=" in self.path:
                self._send(200, "application/json", _EMPTY_JSON)
            elif path.startswith("/wp-json/"):
                self._send(200, "application/json", b"{}")
            elif path == "/" or path.endswith(".html") or path.endswith(".php"):
                self._send(200, "text/html; charset=utf-8", html_bytes)
            else:
                self._send(404, "text/plain", b"Not Found")

        def do_POST(self):
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length:
                self.rfile.read(content_length)
            self._send(200, "application/json", _EMPTY_JSON)

        def do_OPTIONS(self):
            self._send(204, "text/plain", b"")

        def log_message(self, fmt, *args):  # silence access logs
            pass

    return _Handler

def _start_js_server(js_content: str, http_port: int) -> "socketserver.TCPServer":
    """Start a threaded HTTP server on http_port. Returns the server instance."""
    js_bytes = js_content.encode("utf-8", errors="replace")
    template = _HTML_TEMPLATE_MODULE if _is_es_module(js_content) else _HTML_TEMPLATE
    html_bytes = template.encode("utf-8")
    handler = _make_handler(js_bytes, html_bytes, _load_jquery())

    class _ReuseServer(socketserver.TCPServer):
        allow_reuse_address = True

    server = _ReuseServer(("127.0.0.1", http_port), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

def _generate_changed_js_report(out_dir: Path, source_url: str, page_url: str) -> bool:
    """Read the trace, find scriptIds for /target.js, write changed_js_report.json.

    Returns True if target script was found in the trace.
    """
    trace_file = out_dir / "trace_v2.json.zst"
    if not trace_file.exists():
        trace_file = out_dir / "trace_v2.json"
    if not trace_file.exists():
        return False

    try:
        if trace_file.suffix == ".zst":
            with trace_file.open("rb") as fh:
                with zstd.ZstdDecompressor().stream_reader(fh) as reader:
                    data = reader.read()
            events = json.loads(data.decode("utf-8"))
        else:
            with trace_file.open("r", encoding="utf-8") as fh:
                events = json.load(fh)
    except Exception:
        return False

    script_ids = []
    for record in events:
        event = record.get("event") or record
        method = event.get("method", "")
        if method != "Debugger.scriptParsed":
            continue
        params = event.get("params") or {}
        url = params.get("url", "")
        if url.endswith("/target.js"):
            sid = params.get("scriptId")
            if sid:
                script_ids.append(str(sid))

    report = {
        "target_found": len(script_ids) > 0,
        "script_ids": script_ids,
        "source_url": source_url,
        "page_url": page_url,
        "trace_mode": "local_js",
        "matches": [{"script_id": sid, "script_url": "/target.js", "match_reason": "local_target"} for sid in script_ids],
        "notes": [],
    }
    (out_dir / "changed_js_report.json").write_text(json.dumps(report, indent=2))
    return len(script_ids) > 0

def _trace_one(
    entry: dict,
    output_dir: Path,
    trace_timeout: int,
    chrome_binary: str,
    base_chrome_port: int,
    base_http_port: int,
    port_lock: Lock,
    used_ports: set,
    skip_existing: bool,
    idle_seconds: int,
    interaction_seconds: int,
    extended_idle_seconds: int = 0,
) -> dict:
    domain = entry.get("domain", "unknown")
    sig = entry.get("signature", "")
    diff_type = entry.get("diff_type", "")
    source_url = entry.get("source_url", "")
    original_file = entry.get("original_file", "")

    domain_safe = domain.replace("/", "_").replace(":", "")
    sig12 = sig[:12]
    out_dir = output_dir / domain_safe / sig12

    if skip_existing and (out_dir / "trace_v2.json.zst").exists():
        return {"domain": domain, "status": "skipped"}

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "logs").mkdir(exist_ok=True)

    triggered_by = {
        "domain": domain,
        "signature": sig,
        "diff_type": diff_type,
        "source_url": source_url,
        "original_file": original_file,
        "traced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trace_mode": "local_js",
    }
    (out_dir / "triggered_by.json").write_text(json.dumps(triggered_by, indent=2))

    js_path = Path(original_file)
    if not js_path.exists():
        log.warning("[%s] JS not found on disk: %s", domain, original_file)
        triggered_by["trace_status"] = "js_not_found"
        (out_dir / "triggered_by.json").write_text(json.dumps(triggered_by, indent=2))
        return {"domain": domain, "status": "js_not_found"}

    try:
        js_content = js_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        log.error("[%s] Failed to read JS: %s", domain, exc)
        triggered_by["trace_status"] = "read_error"
        (out_dir / "triggered_by.json").write_text(json.dumps(triggered_by, indent=2))
        return {"domain": domain, "status": "read_error"}

    chrome_port = _find_free_port(base_chrome_port, used_ports, port_lock)
    http_port = _find_free_port(base_http_port, used_ports, port_lock)
    userdata_dir = tempfile.mkdtemp(prefix="cdplocaljs_")
    chrome_proc = None
    http_server = None
    status = "error"

    try:
        http_server = _start_js_server(js_content, http_port)

        chrome_cmd = [
            chrome_binary,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--disable-extensions",
            "--disable-default-apps",
            "--no-first-run",
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            f"--remote-debugging-port={chrome_port}",
            f"--user-data-dir={userdata_dir}",
        ]
        with open(out_dir / "logs" / "chrome.log", "w") as chrome_log:
            chrome_proc = subprocess.Popen(
                chrome_cmd,
                stdout=chrome_log,
                stderr=chrome_log,
                preexec_fn=os.setsid,
            )

        if not _wait_chrome_ready(chrome_port, timeout=20):
            log.warning("[%s] Chrome failed to start on port %d", domain, chrome_port)
            return {"domain": domain, "status": "chrome_failed"}

        local_url = f"http://127.0.0.1:{http_port}/"

        cdp_cmd = [
            sys.executable,
            str(CDPSCAN),
            local_url,
            "--port", str(chrome_port),
            "--output-dir", str(out_dir),
            "--submission-domain", domain,
            "--target-diff-signature", sig,
        ]

        cdp_env = os.environ.copy()
        cdp_env["CDP_POST_LOAD_IDLE_SECONDS"] = str(idle_seconds)
        cdp_env["CDP_INTERACTION_CAPTURE_SECONDS"] = str(interaction_seconds)
        cdp_env["CDP_EXTENDED_INTERACTIONS"] = "1"  # always enable for local traces
        if extended_idle_seconds > 0:
            cdp_env["CDP_EXTENDED_IDLE_SECONDS"] = str(extended_idle_seconds)

        cdp_log_path = out_dir / "logs" / "cdpscan_stdout.log"
        with open(cdp_log_path, "w") as cdp_log:
            try:
                subprocess.run(
                    cdp_cmd,
                    stdout=cdp_log,
                    stderr=cdp_log,
                    timeout=trace_timeout,
                    cwd=str(CDPSCAN_CWD),   # ← KEY: monitoring script path resolves here
                    env=cdp_env,
                    preexec_fn=os.setsid,
                )
                status = "ok"
            except subprocess.TimeoutExpired:
                log.warning("[%s] cdpscan timed out after %ds", domain, trace_timeout)
                status = "timeout"
            except Exception as exc:
                log.error("[%s] cdpscan error: %s", domain, exc)
                status = "error"

    except Exception as exc:
        log.error("[%s] Unexpected error: %s", domain, exc)
        status = "error"

    finally:
        if chrome_proc is not None:
            _kill_group(chrome_proc.pid)
        if http_server is not None:
            http_server.shutdown()
        shutil.rmtree(userdata_dir, ignore_errors=True)
        _release_port(chrome_port, used_ports, port_lock)
        _release_port(http_port, used_ports, port_lock)

    triggered_by["trace_status"] = status
    (out_dir / "triggered_by.json").write_text(json.dumps(triggered_by, indent=2))

    if status == "ok":
        found = _generate_changed_js_report(out_dir, source_url, source_url)
        if not found:
            log.warning("[%s] target script /target.js not found in trace (no scriptParsed event)", domain)

    if status not in ("ok", "skipped"):
        log.warning("[%s] %s", domain, status)
    return {"domain": domain, "status": status, "out_dir": str(out_dir)}

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    parser = argparse.ArgumentParser(
        description="Trace JS files from disk via local HTTP server + Chrome CDP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("queue",
                        help="local_js_queue.json produced by build_local_queue.py")
    parser.add_argument("--output-dir", default="",
                        help="Output directory (default: traces/local_js_<TIMESTAMP>)")
    parser.add_argument("--max-concurrent", type=int, default=20,
                        help="Parallel Chrome instances (default: 20). "
                             "Each needs ~300MB RAM.")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Hard timeout per JS in seconds (default: 60)")
    parser.add_argument("--chrome",
                        default=os.getenv("CHROME_BINARY", "google-chrome-stable"),
                        help="Chrome binary (default: google-chrome-stable)")
    parser.add_argument("--chrome-port", type=int, default=9300,
                        help="Base Chrome debug port (default: 9300)")
    parser.add_argument("--http-port", type=int, default=9500,
                        help="Base HTTP server port (default: 9500)")
    parser.add_argument("--skip-existing", action="store_true",
                        help="Skip entries whose output dir already has trace_v2.json.zst")
    parser.add_argument("--idle-seconds", type=int, default=2,
                        help="Seconds to wait after page load before interactions (default: 2, "
                             "cdpscan default is 5). Lower = faster, may miss slow-loading payloads.")
    parser.add_argument("--interaction-seconds", type=int, default=5,
                        help="Seconds to observe after synthetic interactions (default: 5, "
                             "cdpscan default is 10).")
    parser.add_argument("--extended-idle-seconds", type=int, default=0,
                        help="Extra observation seconds after extended interactions (default: 0). "
                             "Increase to catch delayed timers (e.g. --extended-idle-seconds 8 "
                             "will capture setTimeout(fn, 8000)).")
    args = parser.parse_args()

    if not CDPSCAN.exists():
        log.error("cdpscan.py not found at %s", CDPSCAN)
        sys.exit(1)

    try:
        chrome_binary = _find_chrome_binary(args.chrome)
    except RuntimeError as exc:
        log.error("%s", exc)
        sys.exit(1)

    queue_path = Path(args.queue)
    if not queue_path.exists():
        log.error("Queue not found: %s", queue_path)
        sys.exit(1)

    queue = json.loads(queue_path.read_text())
    if not queue:
        log.info("Empty queue — nothing to trace.")
        return

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_dir = (
        Path(args.output_dir).resolve()
        if args.output_dir
        else SCRIPT_DIR / "traces" / f"local_js_{timestamp}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    log.info(
        "Tracing %d JS files | max_concurrent=%d | timeout=%ds | chrome=%s",
        len(queue), args.max_concurrent, args.timeout, chrome_binary,
    )
    log.info("Output → %s", output_dir)
    log.info("cdpscan cwd → %s  (monitoring script will be injected)", CDPSCAN_CWD)

    port_lock = Lock()
    used_ports: set = set()
    results = []
    counters = {"ok": 0, "timeout": 0, "skipped": 0, "failed": 0}

    with ThreadPoolExecutor(max_workers=args.max_concurrent) as pool:
        futures = {
            pool.submit(
                _trace_one,
                entry, output_dir, args.timeout,
                chrome_binary, args.chrome_port, args.http_port,
                port_lock, used_ports, args.skip_existing,
                args.idle_seconds, args.interaction_seconds,
                args.extended_idle_seconds,
            ): entry.get("domain", "?")
            for entry in queue
        }
        total = len(futures)
        with tqdm(total=total, unit="js", dynamic_ncols=True) as bar:
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    log.error("%s raised: %s", domain, exc)
                    result = {"domain": domain, "status": "exception", "error": str(exc)}
                results.append(result)
                status = result.get("status", "failed")
                if status == "ok":
                    counters["ok"] += 1
                elif status == "timeout":
                    counters["timeout"] += 1
                elif status == "skipped":
                    counters["skipped"] += 1
                else:
                    counters["failed"] += 1
                bar.set_postfix(
                    ok=counters["ok"],
                    timeout=counters["timeout"],
                    skip=counters["skipped"],
                    fail=counters["failed"],
                    refresh=False,
                )
                bar.update(1)

    ok = counters["ok"]
    timeout = counters["timeout"]
    skipped = counters["skipped"]
    failed = counters["failed"]

    summary = {
        "total": len(queue),
        "ok": ok,
        "timeout": timeout,
        "skipped": skipped,
        "failed": failed,
        "results": results,
    }
    summary_path = output_dir / "trace_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    log.info(
        "Done. ok=%d timeout=%d skipped=%d failed=%d → %s",
        ok, timeout, skipped, failed, summary_path,
    )

if __name__ == "__main__":
    main()
