import { Component, OnInit } from '@angular/core';
import { CartService } from '../cart/cart-service';
import { AuthService} from '../login/AuthService';
@Component({
  selector: 'taco-header',
  templateUrl: 'header.component.html',
  styleUrls: ['./header.component.css']
})

export class HeaderComponent implements OnInit {
  cart: CartService;

  constructor(cartService: CartService, public authService: AuthService) {
    this.cart = cartService;
  }

  logout(){
	  this.authService.logout();
  }
  ngOnInit() { }
}
