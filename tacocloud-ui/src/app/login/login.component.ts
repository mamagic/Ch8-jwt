import { Component, OnInit } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { FormBuilder, FormGroup } from '@angular/forms';
import { ReactiveFormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService} from '../login/AuthService';
import { ApiResponse} from './Api-response'

@Component({
  selector: 'login-tacocloud',
  templateUrl: 'login.component.html',
  styleUrls: ['./login.component.css']
})

export class LoginComponent implements OnInit {
  sign: FormGroup;
  model: any = {};
  token: String = '';
  constructor(private formBuilder: FormBuilder,
		  		private httpClient: HttpClient,
		  		private router: Router,
		  		public authService: AuthService) {
 	this.sign= this.formBuilder.group({
		username: '',
		password: '',
  	});
  }

  ngOnInit() { }


  onSubmit() {
	  this.model.username = this.sign.value.username;
    this.model.password = this.sign.value.password;

    // this.model.tacos = this.cart.getItemsInCart();
	console.log(this.model.username);
    this.httpClient.post<ApiResponse>(
        'http://localhost:8080/login', this.model)
    	.subscribe( response => {
            // 로그인 성공 처리
            let token = response.token;
            console.log(response);
            this.authService.login();
            this.authService.storeToken(token);
            this.router.navigate(['/']);
    	  },
    	  (error) => {
    	    // 로그인 실패 처리
    	    console.error('Login failed', error);
    	  })
    // TODO: Do something after this...navigate to a thank you page or something
  }

}
