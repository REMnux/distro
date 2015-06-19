//
// Define objects, functions, and methods commonly used by
// malicious browser scripts.
//
// By Lenny Zeltser
//
// Last revised on May 30, 2015
//

original_eval = eval;
eval = function(input_string) {
	print(input_string);
	original_eval(input_string);
}

window = {
	location: {
		// If necessary, set "href" to the proper value
		// href:"http://www.example.com/page"
	},
	navigate: function(input_string) {
		print("/* window.navigate(" + input_string + ") */");
	},
	eval: function(input_string) {
		eval(input_string);
	}
}

location = {
	// If necessary, set "href" to the proper value
	// href:"http://www.example.com/page"
}

document = {
	write:print,
	writeln:print,
	createElement: function(input_string) {
		print("/* document.CreateElement(" + input_string + ") */");
		return {}
	},
	body: {
		appendChild: function(input_string) {
			print(input_string.text);
		}
	},
	// If necessary, set "referrer" to the proper value
	// referrer:"http://www.google.com/search?hl=en&q=web&aq=f&oq=&aqi=g1",
	// If necessary, set "lastModified" to the proper value
	// lastModified:"Thu, 24 Dec 2009 11:08:12 GMT"
};

// The following objects are specific to PDF files

app = {
	setTimeOut: function(arg1, arg2) {
		print("/* app.setTimeOut(" + arg1 + 
		       ", " + arg2 + ") */");
		eval(arg1);
		return {}
	},
	clearTimeOut: function(arg1) {
		print("/* app.clearTimeOut(" + arg1 + ") */");
		return {};
	},
	viewerVersion:"8.1"
};

Collab = {
	collectEmailInfo: function(arg1) {
		print("/* Collab.collectEmailInfo(subj:" + arg1.subj + 
		       ", msg:" + arg1.msg + ") */");
		return {}
	}
}
