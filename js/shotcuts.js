keyboard$.subscribe(function(key) {
    if (key.mode === "global" ) {
        console.log(key);
      switch (key.type) {
        case "x":
            if (key.event === "keyup") {
                key.claim()
                console.log("You pressed /");
            }
            break;
      }
    }
  })