import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';

@Component({
  selector: 'big-button',
  templateUrl: './bigbutton.component.html',
  styleUrls: ['./bigbutton.component.css']
})

export class BigButtonComponent implements OnInit {

  @Input() label: string | undefined;

  @Output() clickEvent = new EventEmitter<void>();

  constructor() { }

  ngOnInit() { }

  onClick() {
    this.clickEvent.emit();
  }
}


//import { Component, Input } from '@angular/core';

//@Component({
//  selector: 'big-button',
//  templateUrl: './bigbutton.component.html',
//  styleUrls: ['./bigbutton.component.css']
//})
//export class BigButtonComponent {
//  @Input() label: string = '';

//  constructor() { }
//}

