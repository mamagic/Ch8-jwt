import { Component, OnInit } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { FormBuilder, FormGroup } from '@angular/forms';
import { ReactiveFormsModule } from '@angular/forms';
import { Router } from '@angular/router'

@Component({
  selector: 'registry-tacocloud',
  templateUrl: 'registry.component.html',
  styleUrls: ['./registry.component.css']
})

export class RegistryComponent implements OnInit {
  
  form: FormGroup;
  model: any = {}; 
  constructor(private formBuilder: FormBuilder, private httpClient: HttpClient, private router: Router) {
 	this.form = this.formBuilder.group({
		username: '',
		password: '',
		verifyPassword: '',
		fullName: '',
		street: '',
		city: '',
		state: '',
		zipCode: '',
		phoneNumber: ''
  	}); 
  }

  ngOnInit() { }


  onSubmit() {
	this.model.username = this.form.value.username;
    this.model.password = this.form.value.password;
    this.model.fullName = this.form.value.fullName;
    this.model.street = this.form.value.street;
    this.model.city = this.form.value.city;
    this.model.state = this.form.value.state;
    this.model.zipCode = this.form.value.zipCode;
    this.model.phoneNumber = this.form.value.phoneNumber;
    
    // this.model.tacos = this.cart.getItemsInCart();
	console.log(this.model.username);
    this.httpClient.post(
        'http://localhost:8080/registry',
        this.model, {
            headers: new HttpHeaders().set('Content-type', 'application/json')
            						  .set('Accept', 'application/json'),
            })
    	.subscribe( response => {
            this.router.navigate(['/login']);
    	  },
    	  (error) => {
    	    // 로그인 실패 처리
    	    console.error('Login failed', error);
    	  });

    // TODO: Do something after this...navigate to a thank you page or something
  }

}